# YAMP (Yet Another Mitm Proxy)

This module provide a basic but yet powerful man in the middle proxy for nodejs.  
It provides _HTTP_ & _HTTPS_ support and also modifying the request and response data.

The main goal of this library is to ease the managment of certificate for https requests.

## History

A huge part has been borrowed from [node-http-mitm-proxy](https://github.com/joeferner/node-http-mitm-proxy) (MIT License).

This fix the [main issue](https://github.com/joeferner/node-http-mitm-proxy/issues/187) that I had using the library by being unable to have the full request's body and still being able to cancel it for the response.

The other feature I added is to allow sequential chaining of middleware. Which is useful if you need to have on middleware to execute before another (and maybe alter the current request).

# How to use it?

```js
const { Proxy } = require('@dblk/yamp');
const mitm = new Proxy();

const options = {
    port: 8080,
    sslCaDir: '.generated-certs',
    timeout: 20000,
};

// First middleware for every requests
mitm.onRequest((req, res, next) => {
    try {
        req.middleware1 = true;
    } catch (err) {
        return next(err);
    }
    next();
});

// Second middleware
mitm.onRequest((req, res, next) => {
    try {
        if (req.middleware1) {
            req.middleware2 = true; 
        }
    } catch (err) {
        return next(err);
    }
    next();
});

mitm.onResponse((req, res, proxyRes, next) => {
    try {
        console.log(res.finished);
    } catch (err) {
        return next(err);
    }
});

// Start the proxy
mitm.listen(options);
```

# SSL

Using `node-forge` allows the automatic generation of SSL certificates within the proxy. After running your app you will find options.sslCaDir + '/certs/ca.pem' which can be imported to your browser, phone, etc.

# What's next?

I did port all of the features that `node-http-mitm-proxy` has to offer and it might be a good starting point to add websocket also.

Please submit an issue on github about what you want next for this librairy.

# API

You will find the documentation of available functions with their according signature bellow.

# API

## Proxy
 * [listen(options)](#proxy_listen)
 * [close](#proxy_close)
 * [onCertificateRequired](#proxy_onCertificateRequired)
 * [onCertificateMissing](#proxy_onCertificateMissing)
 * [onRequest(fn)](#proxy_onRequest)
 * [onResponse(fn)](#proxy_onResponse)

## Proxy

<a name="proxy_listen" />

### proxy.listen

Starts the proxy listening on the given port.

__Arguments__

 * options - An object with the following options:
  * port - The port or named socket to listen on (default: 8080).
  * sslCaDir - Path to the certificates cache directory (default: process.cwd() + '/.http-mitm-proxy')
  * keepAlive - enable [HTTP persistent connection](https://en.wikipedia.org/wiki/HTTP_persistent_connection)
  * timeout - The number of milliseconds of inactivity before a socket is presumed to have timed out. (default: 5000).
  * httpAgent - The [http.Agent](https://nodejs.org/api/http.html#http_class_http_agent) to use when making http requests. Useful for chaining proxys. (default: internal Agent)
  * httpsAgent - The [https.Agent](https://nodejs.org/api/https.html#https_class_https_agent) to use when making https requests. Useful for chaining proxys. (default: internal Agent)

__Example__

    proxy.listen({ port: 80 });

<a name="proxy_close" />

### proxy.close

Stops the proxy listening.

__Example__

    proxy.close();

<a name="proxy_onCertificateRequired" />

### proxy.onCertificateRequired = function(hostname, callback)

Allows the default certificate name/path computation to be overwritten.

The default behavior expects `keys/{hostname}.pem` and `certs/{hostname}.pem` files to be at `self.sslCaDir`.

__Arguments__

 * hostname - Requested hostname.
 * callback - The function to be called when certificate files' path were already computed.

__Example 1__

    proxy.onCertificateRequired = function(hostname, callback) {
      return callback(null, {
        keyFile: path.resolve('/ca/certs/', hostname + '.key'),
        certFile: path.resolve('/ca/certs/', hostname + '.crt')
      });
    };

__Example 2: Wilcard certificates__

    proxy.onCertificateRequired = function(hostname, callback) {
      return callback(null, {
        keyFile: path.resolve('/ca/certs/', hostname + '.key'),
        certFile: path.resolve('/ca/certs/', hostname + '.crt'),
        hosts: ["*.mydomain.com"]
      });
    };


<a name="proxy_onCertificateMissing" />

### proxy.onCertificateMissing = function(ctx, files, callback)

Allows you to handle missing certificate files for current request, for example, creating them on the fly.

__Arguments__

* ctx - Context with the following properties
 * hostname - The hostname which requires certificates
 * data.keyFileExists - Whether key file exists or not
 * data.certFileExists - Whether certificate file exists or not
* files - missing files names (`files.keyFile`, `files.certFile` and optional `files.hosts`)
* callback - The function to be called to pass certificate data back (`keyFileData` and `certFileData`)

__Example 1__

    proxy.onCertificateMissing = function(ctx, files, callback) {
      console.log('Looking for "%s" certificates',   ctx.hostname);
      console.log('"%s" missing', ctx.files.keyFile);
      console.log('"%s" missing', ctx.files.certFile);

      // Here you have the last chance to provide certificate files data
      // A tipical use case would be creating them on the fly
      //
      // return callback(null, {
      //   keyFileData: keyFileData,
      //   certFileData: certFileData
      // });
      };

__Example 2: Wilcard certificates__

    proxy.onCertificateMissing = function(ctx, files, callback) {
      return callback(null, {
        keyFileData: keyFileData,
        certFileData: certFileData,
        hosts: ["*.mydomain.com"]
      });
    };


<a name="proxy_onRequest" />

### proxy.onRequest(fn)

Adds a function to get called at the beginning of a request.

__Arguments__

 * fn(req, res, next) - The function that gets called on each request.
   * req - The initial [http.request](https://nodejs.org/api/http.html#http_class_http_clientrequest) object 
   * res - The [http.response](https://nodejs.org/api/http.html#http_class_http_serverresponse) to the client 
   * next - Call the next middleware (Pass an object to set the error)

__Example__

    proxy.onRequest(function(req, res, next) {
      console.log('REQUEST:', req.url);
      next();
    });

<a name="proxy_onResponse" />

### proxy.onResponse(fn)

Adds a function to get called at the beginning of the response.

__Arguments__

 * fn(req, res, proxyRes, next) - The function that gets called on each response.
   * req - The initial [http.request](https://nodejs.org/api/http.html#http_class_http_clientrequest) object 
   * res - The [http.response](https://nodejs.org/api/http.html#http_class_http_serverresponse) to the client 
   * proxyRes - The [http.response](https://nodejs.org/api/http.html#http_class_http_serverresponse) from the remote server
   * next - Call the next middleware (Pass an object to set the error)

__Example__

    proxy.onResponse(function(req, res, proxyRes, next) {
      if (res.finished) {
          console.log('Response ended before reaching me, can't modify');
          next();
          return;
      }
      console.log('BEGIN RESPONSE');
      if (proxyRes.statusCode !== 200) {
          res.statusCode = 500;
      } else {
          res.statusCode = 200;
      }
      res.end(proxyRes.rawBody);
      next();
    });

# License

```
Copyright (c) 2019 Rémy Boulanouar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:



The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.



THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
