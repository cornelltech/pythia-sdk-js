'use strict';

var request = require('request');
var bcrypt = require('bcryptjs');

//module levels variables
var _serverURL;
var _clientSelector;

// setup (provide key)
function setup(selector, pythiaServerURL) {
  _clientSelector = selector;
  _serverURL = pythiaServerURL;
}

var separatorCharacter = '$'

function genTweak(callback) {
  bcrypt.genSalt(10, function(error, salt) {

    if (error) {
      return callback(error, null);
    }

    //generates salt in format $2a$10$
    var a = salt.split(separatorCharacter);
    return callback(null, a[3]);

  });
}

function encodePythiaPassword(passwordObject) {

  var pythiaPasswordString = ["", passwordObject.type, passwordObject.tweak, passwordObject.salt.replace("$2a$10$", ""), passwordObject.pythiaHash].join(separatorCharacter);
  return pythiaPasswordString;
}

function decodePythiaPassword(pythiaPasswordString) {

  var pythiaPasswordArray = pythiaPasswordString.split(separatorCharacter);
  //note that salt must be in $2a$10$* format, must join

  var passwordObject = {
    type: pythiaPasswordArray[1],
    tweak: pythiaPasswordArray[2],
    salt: "$2a$10$" + pythiaPasswordArray[3],
    pythiaHash: pythiaPasswordArray[4]
  }

  return passwordObject;
}

function eval_unb(password, tweak, callback) {
  var baseURL = _serverURL;
  var params  = {
    w: _clientSelector,
    t: tweak,
    x: password
  }

  request({
    method: 'GET',
    url: baseURL + '/pythia/eval-unb',
    qs: params,
    json: true
  }, function (error, response, body) {
      if (error) {
        return callback(error, null);
      }

      if(response.statusCode == 200){

        return callback(null, body.y);
      } else {
        console.error('error: '+ response.statusCode)
        console.error(body)
        return callback(error, false);
      }
    });
}



// hash
function hash(password, callback) {

  //generate new tweak
  genTweak(function(error, tweak) {
    if (error) {
        return callback(error);
    }

    bcrypt.genSalt(10, function(error, salt) {

      if (error) {
        return callback(error, null);
      }

      bcrypt.hash(password, salt, function(error, crypted) {

        if (error) {
          return callback(error, null);
        }

        var hashedPassword = crypted.replace(salt, "");

        eval_unb(hashedPassword, tweak, function(error, hash) {
          if (error) {
              return callback(error);
          }

          if (!hash) {
              return callback(null, false);
          }

          var encodedPythiaPassword = encodePythiaPassword( {
            type: "pythia_unb",
            tweak: tweak,
            salt: salt,
            pythiaHash: hash
          });

          //this is what is saved in the db password field
          callback(null, encodedPythiaPassword);
        });

      });

    });


  })

}

// compare
function compare(password, encodedPythiaPassword, callback) {

  var passwordObject = decodePythiaPassword(encodedPythiaPassword);

  bcrypt.hash(password, passwordObject.salt, function(error, crypted) {

    if (error) {
      return callback(error, null);
    }

    var hashedPassword = crypted.replace(passwordObject.salt, "");

    eval_unb(hashedPassword, passwordObject.tweak, function(error, hash) {
      if (error) {
          return callback(err);
      }

      if (!hash) {
          return callback(null, false);
      }

      if (hash == passwordObject.pythiaHash) {
        return callback(null, true);
      }
      else {
        return callback(null, false);
      }

    });

  });


}


module.exports = {
    setup: setup,
    hash: hash,
    compare: compare
};
