
#include <cstdio>
#include <string>
#include "ppapi/cpp/instance.h"
#include "ppapi/cpp/module.h"
#include "ppapi/cpp/var.h"
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"


namespace {
  const char* const kGenerateRSAKey = "generate_rsa_key";
}
class RSAInstance : public pp::Instance {
 public:
  /// The constructor creates the plugin-side instance.
  /// @param[in] instance the handle to the browser-side plugin instance.
  explicit RSAInstance(PP_Instance instance) : pp::Instance(instance)
  {}
  virtual ~RSAInstance() {}

  /// Handler for messages coming in from the browser via postMessage().  The
  /// @a var_message can contain anything: a JSON string; a string that encodes
  /// method names and arguments; etc.  For example, you could use
  /// JSON.stringify in the browser to create a message that contains a method
  /// name and some parameters, something like this:
  ///   var json_message = JSON.stringify({ "myMethod" : "3.14159" });
  ///   nacl_module.postMessage(json_message);
  /// On receipt of this message in @a var_message, you could parse the JSON to
  /// retrieve the method name, match it to a function call, and then call it
  /// with the parameter.
  /// @param[in] var_message The message posted by the browser.
  virtual void HandleMessage(const pp::Var& var_message) {
      if (!var_message.is_string()) {
        return;
      }
      std::string message = var_message.AsString();

      if (message == kGenerateRSAKey) {
        std::string data;
        pp::Var var_reply;
        byte outByte;

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSA::PrivateKey privateKey;

        privateKey.GenerateRandomWithKeySize(rng, 2048);

        CryptoPP::ByteQueue queue;
        privateKey.DEREncodePrivateKey(queue);

        while (queue.Get(outByte) != 0) {
          data += outByte;
        }

        var_reply = pp::Var(data);

        PostMessage(var_reply);
      }

      return;
  }
};

/// The Module class.  The browser calls the CreateInstance() method to create
/// an instance of your NaCl module on the web page.  The browser creates a new
/// instance for each <embed> tag with type="application/x-nacl".
class RSAModule : public pp::Module {
 public:
  RSAModule() : pp::Module() {}
  virtual ~RSAModule() {}

  /// Create and return a RSAInstance object.
  /// @param[in] instance The browser-side instance.
  /// @return the plugin-side instance.
  virtual pp::Instance* CreateInstance(PP_Instance instance) {
    return new RSAInstance(instance);
  }
};

namespace pp {
/// Factory function called by the browser when the module is first loaded.
/// The browser keeps a singleton of this module.  It calls the
/// CreateInstance() method on the object you return to make instances.  There
/// is one instance per <embed> tag on the page.  This is the main binding
/// point for your NaCl module with the browser.
Module* CreateModule() {
  return new RSAModule();
}
}  // namespace pp
