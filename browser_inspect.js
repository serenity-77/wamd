// From:
// https://github.com/sigalor/whatsapp-web-multi-device-reveng/blob/main/inspect-app.md

(function()
{
    if (!window.mR) {
        const moduleRaid = function () {
          moduleRaid.mID  = Math.random().toString(36).substring(7);
          moduleRaid.mObj = {};

          fillModuleArray = function() {
            (window.webpackChunkbuild || window.webpackChunkwhatsapp_web_client).push([
              [moduleRaid.mID], {}, function(e) {
                Object.keys(e.m).forEach(function(mod) {
                  moduleRaid.mObj[mod] = e(mod);
                })
              }
            ]);
          }

          fillModuleArray();

          get = function get (id) {
            return moduleRaid.mObj[id]
          }

          findModule = function findModule (query) {
            results = [];
            modules = Object.keys(moduleRaid.mObj);

            modules.forEach(function(mKey) {
              mod = moduleRaid.mObj[mKey];

              if (typeof mod !== 'undefined') {
                if (typeof query === 'string') {
                  if (typeof mod.default === 'object') {
                    for (key in mod.default) {
                      if (key == query) results.push(mod);
                    }
                  }

                  for (key in mod) {
                    if (key == query) results.push(mod);
                  }
                } else if (typeof query === 'function') {
                  if (query(mod)) {
                    results.push(mod);
                  }
                } else {
                  throw new TypeError('findModule can only find via string and function, ' + (typeof query) + ' was passed');
                }

              }
            })

            return results;
          }

          return {
            modules: moduleRaid.mObj,
            constructors: moduleRaid.cArr,
            findModule: findModule,
            get: get
          }
        }

        window.mR = moduleRaid();
    }


    if (!window.decodeStanza) {
        window.decodeStanza = (window.mR.findModule('decodeStanza')[0]).decodeStanza;
        window.encodeStanza = (window.mR.findModule('encodeStanza')[0]).encodeStanza;
        window.encodeProtobuf = (window.mR.findModule('encodeProtobuf')[0]).encodeProtobuf;
        window.decodeProtobuf = (window.mR.findModule('decodeProtobuf')[0]).decodeProtobuf;
    }

    (window.mR.findModule('decodeStanza')[0]).decodeStanza = async (e, t) => {
        const result = await window.decodeStanza(e, t);
        console.log("DECODE STANZA", new Uint8Array(e).toString("hex"));
        return result;
    }

    (window.mR.findModule('encodeStanza')[0]).encodeStanza = (...args) => {
        const result = window.encodeStanza(...args);

        console.log('ENCODE STANZA', args, "->", result.toString("hex"));
        return result;
    }

    (window.mR.findModule('encodeProtobuf')[0]).encodeProtobuf = (...args) => {
        const result = window.encodeProtobuf(...args);

        console.log('ENCODE PROTOBUF', args, "->", result._buffer.toString("hex"));
        return result;
    }

    (window.mR.findModule('decodeProtobuf')[0]).decodeProtobuf = (...args) => {
        const result = window.decodeProtobuf(...args);

        console.log('DECODE PROTOBUF', args, "->", result);
        return result;
    }

    var oldSend = window.WebSocket.prototype.send
    window.WebSocket.prototype.send = function(e){
        console.log("send", e.toString("hex"))
        return oldSend.call(this, e)
    }
})()
