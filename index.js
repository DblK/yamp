const { EventEmitter } = require('events');
const debug = require('debug')('yamp:proxy');
const http = require('http');
const https = require('https');
const connect = require('connect');
const bodyParser = require('body-parser');
const url = require('url');
const fs = require('fs');
const path = require('path');
const semaphore = require('semaphore');
const ca = require('./ca.js');
const net = require('net');

const async = require('async'); // TODO: remove once refactor complete

class ErrorWithCode extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/**
 * Allow to execute resolve this promise after ms or param promise
 *
 * @param {Number} ms Number of millisecond to timeout
 * @param {Promise} promise Promise to race against timeout
 */
const promiseTimeout = (ms, promise) => {
  const timeout = new Promise((_resolve, reject) => {
    debug(`Timeout in ${ms}ms`);
    const id = setTimeout(() => {
      clearTimeout(id);
      reject(new ErrorWithCode('ERR_TIMEOUT_PROMISE', `Timed out in ${ms}ms.`));
    }, ms);
  });

  return Promise.race([timeout, promise]);
};

class Proxy extends EventEmitter {
  /**
   *
   * @constructor
   */
  constructor() {
    super();
    debug('constructor');

    this.requestHandlers = [];
    this.responseHandlers = [];
    this.connectRequests = [];

    this.app = connect();

    // Retrieve whole body request
    const rawBodyParser = (req, _res, buf) => {
      if (buf && buf.length) {
        req.rawBody = buf;
      } else {
        req.rawBody = null;
      }
    };
    this.app.use(bodyParser.json({ verify: rawBodyParser }));
    this.app.use(bodyParser.urlencoded({ extended: false, verify: rawBodyParser }));

    // No encoding (raw only)
    this.onRequest((req, _res, next) => {
      delete req.headers['accept-encoding'];
      next();
    });

    /**
     * Handle all beforeRequest
     *
     * @param {beforeRequestHandler} fn A function to execute
     */
    this.app.use((req, res, next) => {
      // Fix req.url for https query
      if (req.url.indexOf('http') === -1) {
        req.url = (!req.isSsl ? req.url : `https://${req.headers.host}${req.url}`);
      }
      debug(`middleware onBeforeRequest for url '${req.url}'`);

      // Chain all middleware
      const handlers = this.requestHandlers.reduce((promiseChain, fn) => promiseChain.then(() => new Promise((resolve, reject) => {
        const nextFn = (err) => {
          if (err) {
            reject(err);
          }
          resolve();
        };
        try {
          fn(req, res, nextFn);
        } catch (err) {
          reject(err);
        }
      })), Promise.resolve());

      promiseTimeout(this.options.timeout, handlers)
        .catch((err) => {
          if (err.code !== 'ERR_TIMEOUT_PROMISE') {
            next(err);
          }
        })
        .then(() => { // TODO: Use finally instead but need Node 10.0.0 minimum
          if (!res.finished) {
            // Make request to target server
            next();
          }
        });
    });

    // Handle proxing the request
    this.app.use(async (req, res, next) => {
      debug(`proxying request to '${req.url}'`, req.isSsl);
      let answer;
      try {
        answer = await this._handleRequest(req, res, next);
      } catch (err) {
        // Silent Error
        next(err);
        return this;
      }

      // Fix req.url for middlewares
      if (req.url.indexOf('http') === -1) {
        req.url = `${(!req.isSsl ? 'http' : 'https')}://${req.headers.host}${req.url}`;
      }
      debug(`middleware onBeforeResponse for url '${req.url}'`);

      // Chain all middleware
      const handlers = this.responseHandlers.reduce((promiseChain, fn) => promiseChain.then(() => new Promise((resolve, reject) => {
        const nextFn = (err) => {
          if (err) {
            reject(err);
          }
          resolve();
        };
        try {
          fn(req, res, answer, nextFn);
        } catch (err) {
          reject(err);
        }
      })), Promise.resolve());

      return promiseTimeout(this.options.timeout, handlers)
        .catch((err) => {
          if (err.code !== 'ERR_TIMEOUT_PROMISE') {
            debug(err);
            next(err);
          }
        })
        .then(() => { // TODO: Use finally instead but need Node 10.0.0 minimum
          if (!res.finished) {
            res.writeHead(500);
            res.write('Minimalist-MitmProxy Warning');
            res.end();
            // Call next process (hint: there is none :p)
            next();
          }
        });
    });

    return this;
  }

  /**
   * Handle Error happening insode proxy
   *
   * @param {http.ServerResponse} res Response
   * @param {ErrorWithCode} err Error that has been thrown
   * @private
   */
  _onError(res, err) {
    debug('onError');
    if (!res.headersSent) {
      res.writeHead(504, 'Proxy Error');
    }
    if (!res.finished) {
      res.end(`${err.code}: {err.message}`, 'utf8');
    }
  }

  /**
    * Responsible to forward target response to client
    *
    * @param {http.ClientRequest} req Request
    * @param {http.ServerResponse} res Response
    * @param {http.ServerResponse} proxyRes Response
    * @param {Promise} next Pass to the next registered function
   */
  _finalResponse(_req, res, proxyRes, next) {
    debug('_finalResponse');

    if (res.finished) {
      debug("Response ended before me... :'(");
      // End of line for response
      next();
      return;
    }

    try {
      // Prevent resending header
      if (!res.headersSent) {
        Object.keys(proxyRes.headers).forEach((key) => {
          if (proxyRes.headers[key] !== undefined) {
            // https://github.com/nodejitsu/node-http-proxy/issues/362
            if (/^www-authenticate$/i.test(key)) {
              if (proxyRes.headers[key]) {
                proxyRes.headers[key] = proxyRes.headers[key] && proxyRes.headers[key].split(','); // eslint-disable-line no-param-reassign
              }
              key = 'www-authenticate'; // eslint-disable-line no-param-reassign
            }
            res.setHeader(key, proxyRes.headers[key]);
          }
        });

        res.writeHead(proxyRes.statusCode);
        res.end(proxyRes.rawBody);
      }
    } catch (err) {
      throw err;
    }
  }

  /**
    * Make connection to target
    *
    * @param {http.ClientRequest} req Request
    */
  async _handleRequest(req) {
    debug('_handleRequest');
    const proto = req.isSsl ? https : http;
    let proxyReq;

    const hostPort = this.parseHostAndPort(req, req.isSsl ? 443 : 80);
    const rOptions = {
      method: req.method,
      path: req.url,
      host: hostPort.host,
      port: hostPort.port,
      headers: req.headers,
      agent: req.isSsl ? this.httpsAgent : this.httpAgent,
    };

    req.socket.setKeepAlive(true, 30000);

    return new Promise((resolve, reject) => {
      proxyReq = proto.request(rOptions, (proxyRes) => {
        debug('Resolve server request and wait for proxy body end');

        const chunks = [];
        proxyRes.on('data', (chunk) => {
          chunks.push(chunk);
        });
        proxyRes.on('end', () => {
          proxyRes.rawBody = Buffer.concat(chunks); // eslint-disable-line no-param-reassign
          resolve(proxyRes);
        });
      });

      proxyReq.on('timeout', () => {
        reject(new ErrorWithCode('ERR_PROXY_TO_SERVER_TIMEOUT', ', request timeout'));
      });

      proxyReq.on('error', (e) => {
        debug('proxyReq error');
        reject(e);
      });

      proxyReq.on('aborted', () => {
        reject(new ErrorWithCode('ERR_PROXY_TO_SERVER_ABORTED', 'server aborted request'));
        req.abort();
      });

      req.on('aborted', () => {
        debug('req aborted');
        proxyReq.abort();
      });
      proxyReq.end(req.rawBody);
    });
  }

  /**
   * Parse Host and Port
   *
   * @param {http.ClientRequest} req Request
   * @param {Number} defaultPort
   */
  parseHostAndPort(req, defaultPort) {
    const { host } = req.headers;
    if (!host) {
      return null;
    }
    const hostPort = this.parseHost(host, defaultPort);

    // this handles paths which include the full url. This could happen if it's a proxy
    const m = req.url.match(/^http:\/\/([^/]*)\/?(.*)$/);
    if (m) {
      const parsedUrl = url.parse(req.url);
      hostPort.host = parsedUrl.hostname;
      hostPort.port = parsedUrl.port;
      req.url = parsedUrl.path;
    }

    return hostPort;
  }

  /**
   * Split port and host and return separated object
   *
   * @param {*} hostString
   * @param {*} defaultPort
   *
   * @returns {{host: string, port: string}} Separated host and port
   */
  parseHost(hostString, defaultPort) {
    const m = hostString.match(/^http:\/\/(.*)/);
    if (m) {
      const parsedUrl = url.parse(hostString);
      return {
        host: parsedUrl.hostname,
        port: parsedUrl.port,
      };
    }

    const hostPort = hostString.split(':');
    const host = hostPort[0];
    const port = hostPort.length === 2 ? +hostPort[1] : defaultPort;

    return {
      host,
      port,
    };
  }

  /**
    * @callback beforeRequestHandler
    * @param {http.ClientRequest} req Request
    * @param {http.ServerResponse} res Response
    * @param {Promise} next Pass to the next registered function
    */

  /**
   * Register a new handler for event before request
   *
   * @param {beforeRequestHandler} fn A function to execute
   */
  onRequest(fn) {
    if (typeof fn !== 'function') {
      throw new ErrorWithCode('ERR_ONREQUEST_NOT_FUNCTION', 'onRequest param must be a function');
    }
    this.requestHandlers.push(fn);
  }

  /**
    * @callback beforeResponseHandler
    * @param {http.ClientRequest} req Request
    * @param {http.ServerResponse} res Response
    * @param {http.ServerResponse} proxyRes Response
    * @param {Promise} next Pass to the next registered function
    */

  /**
   * Register a new handler for event before response
   *
   * @param {beforeResponseHandler} fn A function to execute
   */
  onResponse(fn) {
    if (typeof fn !== 'function') {
      throw new ErrorWithCode('ERR_ONRESPONSE_NOT_FUNCTION', 'onResponse param must be a function');
    }
    this.responseHandlers.push(fn);
  }

  listen(options) {
    const that = this;
    this.options = options || { port: 8080, timeout: 5000 };

    this.keepAlive = !!options.keepAlive;
    this.httpAgent = typeof (options.httpAgent) !== 'undefined' ? options.httpAgent : new http.Agent({ keepAlive: this.keepAlive });
    this.httpsAgent = typeof (options.httpsAgent) !== 'undefined' ? options.httpsAgent : new https.Agent({ keepAlive: this.keepAlive });
    this.sslServers = {};
    this.sslSemaphores = {};
    this.sslCaDir = options.sslCaDir || path.resolve(process.cwd(), '.minimalist-mitm-proxy');

    // Create CA and launch server
    ca.create(this.sslCaDir, (err, certificationAuthority) => {
      if (err) {
        throw (err);
      }
      that.ca = certificationAuthority;
      // Add Final Response handler
      that.onResponse(that._finalResponse);

      // Create a HTTP Server
      that.httpServer = http.createServer(that.app).listen(options.port);

      // Handle HTTPS
      that.httpServer.on('connect', that._connectHandler.bind(that));
    });
  }

  /**
   * Close the proxy
   */
  close() {
    const that = this;

    this.httpServer.close();
    delete this.httpServer;
    if (this.sslServers) {
      Object.keys(this.sslServers).forEach((srv) => {
        const { server } = that.sslServers[srv];
        if (server) {
          server.close();
        }
        delete that.sslServers[srv];
      });
    }

    return this;
  }

  /**
   * Connect handler (for HTTPS)
   *
   * @param {http.IncomingMessage} req Request
   * @param {net.Socket} socket Network socket between client and server
   * @param {Buffer} head The first packet of upgraded stream
   */
  _connectHandler(req, socket, head) {
    const that = this;

    if (!head || head.length === 0) {
      socket.once('data', that._onConnectData.bind(that, req, socket));
      socket.write('HTTP/1.1 200 OK\r\n');
      if (this.keepAlive && req.headers['proxy-connection'] === 'keep-alive') {
        socket.write('Proxy-Connection: keep-alive\r\n');
        socket.write('Connection: keep-alive\r\n');
      }
      socket.write('\r\n');
      return;
    }
    this._onConnectData(req, socket, head);
  }

  /**
   * Connect data handler (for HTTPS)
   *
   * @param {http.IncomingMessage} req Request
   * @param {net.Socket} socket Network socket between client and server
   * @param {Buffer} head The first packet of upgraded stream
   */
  _onConnectData(req, socket, head) {
    const that = this;
    debug('_onConnectData');
    socket.pause();

    if (head[0] === 0x16 || head[0] === 0x80 || head[0] === 0x00) {
      debug('Encrypted');
      // URL is in the form 'hostname:port'
      const hostname = req.url.split(':', 2)[0];
      const sslServer = this.sslServers[hostname];
      if (sslServer) {
        return that.makeConnection(sslServer.port, req, socket, head);
      }
      // eslint-disable-next-line no-useless-escape
      const wildcardHost = hostname.replace(/[^\.]+\./, '*.');
      let sem = that.sslSemaphores[wildcardHost];
      if (!sem) {
        that.sslSemaphores[wildcardHost] = semaphore(1);
        sem = that.sslSemaphores[wildcardHost];
      }
      // eslint-disable-next-line consistent-return
      sem.take(() => {
        if (that.sslServers[hostname]) {
          process.nextTick(sem.leave.bind(sem));
          return that.makeConnection(that.sslServers[hostname].port, req, socket, head);
        }
        if (that.sslServers[wildcardHost]) {
          process.nextTick(sem.leave.bind(sem));
          that.sslServers[hostname] = {
            port: that.sslServers[wildcardHost],
          };
          return that.makeConnection(that.sslServers[hostname].port, req, socket, head);
        }
        that.getHttpsServer(hostname, (err, port) => {
          process.nextTick(sem.leave.bind(sem));
          if (err) {
            throw err;
            //   return that._onError('OPEN_HTTPS_SERVER_ERROR', null, err);
          }
          return that.makeConnection(port, req, socket, head);
        });
      });
    } else {
      debug('Not encrypted');
      return that.makeConnection(this.httpPort, req, socket, head);
    }
    return null;
  }

  /**
   * Make a https server for a specific hostname
   *
   * @param {*} hostname
   * @param {*} callback
   */
  getHttpsServer(hostname, callback) {
    const that = this;

    // eslint-disable-next-line consistent-return
    that.onCertificateRequired(hostname, (err, files) => {
      if (err) {
        return callback(err);
      }
      async.auto({
        keyFileExists(cb1) {
          return fs.exists(files.keyFile, exists => cb1(null, exists));
        },
        certFileExists(cb2) {
          return fs.exists(files.certFile, exists => cb2(null, exists));
        },
        httpsOptions: ['keyFileExists', 'certFileExists', function noUnameFunction(data, cb3) {
          if (data.keyFileExists && data.certFileExists) {
            return fs.readFile(files.keyFile, (errKeyFile, keyFileData) => {
              if (errKeyFile) {
                return cb3(errKeyFile);
              }

              return fs.readFile(files.certFile, (errCertFile, certFileData) => {
                if (errCertFile) {
                  return cb3(errCertFile);
                }

                return cb3(null, {
                  key: keyFileData,
                  cert: certFileData,
                  hosts: files.hosts,
                });
              });
            });
          }
          const ctx = {
            hostname,
            files,
            data,
          };

          return that.onCertificateMissing(ctx, files, (errCertMissing, filesMissing) => {
            if (errCertMissing) {
              return cb3(errCertMissing);
            }

            return cb3(null, {
              key: filesMissing.keyFileData,
              cert: filesMissing.certFileData,
              hosts: filesMissing.hosts,
            });
          });
        }],
      // eslint-disable-next-line consistent-return
      }, (errFinal, results) => {
        if (errFinal) {
          return callback(errFinal);
        }
        let hosts;
        if (results.httpsOptions && results.httpsOptions.hosts && results.httpsOptions.hosts.length) {
          ({ hosts } = results.httpsOptions);
          if (hosts.indexOf(hostname) === -1) {
            hosts.push(hostname);
          }
        } else {
          hosts = [hostname];
        }
        delete results.httpsOptions.hosts; // eslint-disable-line no-param-reassign
        debug(`starting server for ${hostname}`);
        results.httpsOptions.hosts = hosts; // eslint-disable-line no-param-reassign
        that._createHttpsServer(results.httpsOptions, (port, httpsServer) => {
          debug('https server started for %s on %s', hostname, port);
          const sslServer = {
            server: httpsServer,
            port,
          };
          that.sslServers[hostname] = sslServer;
          return callback(null, port);
        });
      });
    });
  }

  _createHttpsServer(options, callback) {
    debug('_createHttpsServer');
    const httpsServer = https.createServer(options);
    httpsServer.timeout = this.timeout;
    httpsServer.on('error', (err) => {
      try {
        throw new ErrorWithCode('ERR_HTTPS_SERVER_ERROR', err);
      } catch (errError) {
        debug(errError);
      }
    });
    httpsServer.on('clientError', (err) => {
      try {
        throw new ErrorWithCode('ERR_HTTPS_CLIENT_ERROR', err);
      } catch (errClient) {
        debug(errClient);
      }
    });
    httpsServer.on('connect', this._connectHandler.bind(this));
    httpsServer.on('request', (req, res) => { req.isSsl = true; this.app(req, res); });
    const listenArgs = [function NoUnamedFunction() {
      if (callback) callback(httpsServer.address().port, httpsServer);
    }];
    // Using listenOptions to bind the server to a particular IP if requested via options.host
    // port 0 to get the first available port
    const listenOptions = {
      port: 0,
    };
    if (this.httpsPort && !options.hosts) {
      listenOptions.port = this.httpsPort;
    }
    if (this.httpHost) { listenOptions.host = this.httpHost; }
    listenArgs.unshift(listenOptions);

    httpsServer.listen(...listenArgs);
  }

  makeConnection(port, req, socket, head) {
    debug('makeConnection');
    const that = this;

    // open a TCP connection to the remote host
    const conn = net.connect({
      port,
      allowHalfOpen: true,
    }, () => {
      // create a tunnel between the two hosts
      conn.on('finish', () => {
        socket.destroy();
      });
      const connectKey = `${conn.localPort}:${conn.remotePort}`;
      that.connectRequests[connectKey] = req;
      socket.pipe(conn);
      conn.pipe(socket);
      socket.emit('data', head);
      conn.on('end', () => { delete that.connectRequests[connectKey]; });
      return socket.resume();
    });
    conn.on('error', (err) => { that._filterSocketConnReset(err, 'PROXY_TO_PROXY_SOCKET'); });
    socket.on('error', (err) => { that._filterSocketConnReset(err, 'CLIENT_TO_PROXY_SOCKET'); });
  }

  // Since node 0.9.9, ECONNRESET on sockets are no longer hidden
  _filterSocketConnReset(err, socketDescription) {
    debug('_filterSocketConnReset');
    if (err.errno === 'ECONNRESET') {
      debug(`Got ECONNRESET on ${socketDescription}, ignoring.`);
    } else {
      throw err;
      // self._onError(socketDescription + '_ERROR', null, err);
    }
  }

  onCertificateRequired(hostname, callback) {
    const self = this;
    return callback(null, {
      keyFile: `${self.sslCaDir}/keys/${hostname}.key`,
      certFile: `${self.sslCaDir}/certs/${hostname}.pem`,
      hosts: [hostname],
    });
  }

  onCertificateMissing(ctx, files, callback) {
    const hosts = files.hosts || [ctx.hostname];
    this.ca.generateServerCertificateKeys(hosts, (certPEM, privateKeyPEM) => {
      callback(null, {
        certFileData: certPEM,
        keyFileData: privateKeyPEM,
        hosts,
      });
    });
    return this;
  }
}

module.exports = {
  Proxy,
};
