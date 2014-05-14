/*!
 * Samsaara - Authentication Methods for Redis
 * Copyright(c) 2014 Arjun Mehta <arjun@newlief.com>
 * MIT Licensed
 */


var authentication = require('./main');

var debug = require('debug')('samsaara:authentication:ipcRedis');
var debugError = require('debug')('samsaara:authentication:ipcRedis:error');

var helper = require('./helper');

var config, ipc;

exports = module.exports;


/*
 * User Session Methods
 */

exports.initialize = function(samsaaraConfig, samsaaraIpc){
  config = samsaaraConfig;
  ipc = samsaaraIpc;
};


var validUserSession = exports.validUserSession = function(sessionID, userID, callBack){

  debug("Valid User Session", sessionID, userID);

  if(sessionID !== undefined && userID !== undefined){
    ipc.store.hget("userSessions", userID, function (err, reply){


      debug("Valid UserSession Result", err, reply);

      if(err !== null){
        debugError("Valid User Session Error", "USER SESSION QUERY ERROR:", err);
        // if(typeof callBack === "function") callBack(null, null);
        debug("validUserSession Error", err);
      }

      if(reply !== null){

        debug("validUserSession Reply", reply);

        var theUsersSessions = JSON.parse(reply);

        if(theUsersSessions[sessionID] !== undefined){
          if(typeof callBack === "function") callBack(null, theUsersSessions);
        }
        else if(theUsersSessions !== undefined){
          if(typeof callBack === "function") callBack("sessionUnregistered", theUsersSessions);
        }
      }
      else{
        if(typeof callBack === "function") callBack("userIDUnregistered", null);
      }
    });
  }
  else{
    if(typeof callBack === "function") callBack("Incorrect number of Parameters", null);
  }

};

exports.addUserSession = function (sessionID, userID, callBack){

  ipc.store.hset("samsaara:sessions", sessionID, userID, function (err, reply){
    addRedisUserSession(sessionID, userID, function (err, reply){
      if(typeof callBack === "function") callBack (err, true);
    });
  });

  debug("Add User Session", "Trying to add Redis Session");
};

exports.removeUserSession = function(sessionID, userID, callBack){

  ipc.store.hdel("samsaara:sessions", sessionID, function (err, reply){
  });

  validUserSession(sessionID, userID, function (err, userSessions){

    if(userSessions !== null && userSessions[sessionID] !== undefined){

      delete userSessions[sessionID];
      if(Object.keys(userSessions).length === 0){
        ipc.store.hdel("userSessions", userID, function (err, reply){
          if(typeof callBack === "function") callBack(err, reply);
        });
      }
      else{
        
        ipc.store.hset("userSessions", userID, JSON.stringify(userSessions), function (err, reply){
          if(!err)
            if(typeof callBack === "function") callBack(err, reply);
          else{
            debug("remove User Session Error:", "REDIS USER SESSION DELETE ERROR", err);
          }
        });
      }
    }
    else{
      if(typeof callBack === "function") callBack("User Session or Session ID do not exist", null);
    }
  });
};

exports.updateUserSession = function(userID, userSessions, callBack){

  ipc.store.hset("userSessions", userID, JSON.stringify(userSessions), function (err, reply){
    if(!err){
      if(typeof callBack === "function") callBack(null, userSessions);
    }
    else{
      debugError("Update User Session Error:", "REDIS USER SESSION DELETE ERROR", err);
      if(typeof callBack === "function") callBack(err, null);
    }
  });

};

exports.addNewConnectionSession = function(connID, userID, sessionID, userSessions, callBack){

  userSessions[sessionID][connID] = 1;

  ipc.store.hset("userSessions", userID, JSON.stringify(userSessions), function (err, reply){
    if(err === null){
      if(typeof callBack === "function") callBack(null, userSessions);
    }
    else{
      debug("Add New Connection Session", "Error", err);
      if(typeof callBack === "function") callBack(err, null);
    }
  });
};





/*
 * Redis User Session Methods
 */

function addRedisUserSession(sessionID, userID, callBack){

  debug("Add Redis User Session Testing", sessionID, userID);

  validUserSession(sessionID, userID, function(err, theUsersSessions){

    if(err === "sessionUnregistered" && theUsersSessions !== null){

      debug("Valid User Session", "UserID exists and session unregistered on Redis");

      registerRedisUserSession(theUsersSessions, sessionID, userID, function (err, reply){
        if(err){
          if(typeof callBack === "function") callBack(err, null);
        }
        else{
          if(typeof callBack === "function") callBack(null, reply);
        }
      });
    }
    else if(err === "userIDUnregistered" && theUsersSessions === null){

      debugError("Invalid User Session", "User ID doesn't exist, creating new Redis Hash");

      registerRedisUserSession({}, sessionID, userID, function (err, reply){

        debug("Register Redis User Session", err, reply);

        if(err !== null){
          if(typeof callBack === "function") callBack(err, null);
        }

        else{
          // ipc.subscribe("USR:" + userID);
          if(typeof callBack === "function") callBack(null, reply);
        }
      });
    }
    else if(err === null && theUsersSessions !== null){ // very very unlikely
      debugError("Invalid User Session", "REDIS Session Addition for User", userID, sessionID, "already exists"); // Session Exists already!
      if(typeof callBack === "function") callBack("existsAlready", null);
    }
    else{
      debugError("Invalid User Session Settings", "REDIS Incorrect/Invalid Setting for Redis Session Addition", userID, sessionID); // notValid Input
      if(typeof callBack === "function") callBack("invalid", null);
    }
  });
}

function registerRedisUserSession(theUsersSessions, sessionID, userID, callBack){

  theUsersSessions[sessionID] = {};

  ipc.store.hset("userSessions", userID, JSON.stringify(theUsersSessions), function (err, reply){
    if(typeof callBack === "function") callBack(err, reply);
  });
}


/*
 * Session Info Methods
 */

exports.getRequestSessionInfo = function(sessionID, callBack){

  ipc.store.hget("samsaara:sessions", sessionID, function (err, userID){
    if(typeof callBack === "function") callBack(sessionID, userID);
  });

};


/*
 * Registration Token Methods
 */

exports.generateRegistrationToken = function(connID, callBack){

  var tokenSalt = helper.makeIdAlpha(22);
  var regtoken = helper.makeUniqueHash("sha1", "Registration Key", [connID.toString(), tokenSalt]);

  ipc.store.setex("samsaara:regtoken:" + regtoken, 10, tokenSalt, function (err, reply){
    if(typeof callBack === "function") callBack(null, regtoken);
  });
};

exports.retrieveRegistrationToken = function(regtoken, callBack){
  ipc.store.get("samsaara:regtoken:" + regtoken, function (err, reply){

    if(err === null && reply !== null){
      if(typeof callBack === "function") callBack(null, reply);
    }
    else{
      if(typeof callBack === "function") callBack(new Error("Invalid Registration Token"), null);
    }
  });
};

exports.validateRegistrationToken = function(connID, regtoken, tokenSalt, callBack){

  ipc.store.get("samsaara:regtoken:" + regtoken, function (err, reply){

    debug("Validate Registration Token", "Auth Store Redis", "VALIDATING REGISTRATION TOKEN FOR", connID, err, reply, tokenSalt);

    if(err === null){
      if(tokenSalt === reply){

        var regtokenGen = helper.makeUniqueHash("sha1", "Registration Key", [connID.toString(), tokenSalt]);

        if(regtokenGen === regtoken){
          if(typeof callBack === "function") callBack(null, true);
        }
        else{
          if(typeof callBack === "function") callBack(new Error("tokenMismatch"), false);
        }
      }
      else{
        if(typeof callBack === "function") callBack(new Error("tokenKeyMismatch"), false);
      }

      ipc.store.del("samsaara:regtoken:" + regtoken, function (err, reply){
      });
    }
    else{
      if(typeof callBack === "function") callBack(new Error("invalidRegistrationToken"), false);
    }
  });
};
