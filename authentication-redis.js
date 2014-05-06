/*!
 * Samsaara - Authentication Methods for Redis
 * Copyright(c) 2013 Arjun Mehta <arjun@newlief.com>
 * MIT Licensed
 */

var authentication = require('./main');

var path = require("path");
var helper = require('./helper');
var moduleName = path.basename(module.filename);
var processID = process.pid.toString();
var config, ipc;

exports = module.exports;


/**
 * User Session Methods
 */

exports.initialize = function(samsaaraConfig, samsaaraIpc){
  config = samsaaraConfig;
  ipc = samsaaraIpc;
};


var validUserSession = exports.validUserSession = function(sessionID, userID, callBack){

  console.log("validUserSession", sessionID, userID);

  if(sessionID !== undefined && userID !== undefined){
    ipc.store.hget("userSessions", userID, function (err, reply){


      console.log("validUserSession Result", err, reply);

      // log.info(processID, moduleName, "REDIS SESSION VALIDATION", err, reply);

      if(err !== null){
        // log.error(processID, moduleName, "USER SESSION QUERY ERROR:", err);
        // if(typeof callBack === "function") callBack(null, null);
        console.log("validUserSession Error", err);
      }

      if(reply !== null){

        console.log("validUserSession Reply", reply);


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

  console.log(moduleName, "Trying to add Redis Session");
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
            // log.info(processID, moduleName, "REDIS USER SESSION DELETE ERROR", err);
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
      // log.error(processID, moduleName, "REDIS USER SESSION DELETE ERROR", err);
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
      console.log(processID, moduleName, "REDIS USER SESSION UPDATE ERROR", err);
      if(typeof callBack === "function") callBack(err, null);
    }
  });
};





/**
 * Redis User Session Methods
 */

function addRedisUserSession(sessionID, userID, callBack){

  console.log("addRedisUserSession Testing", sessionID, userID);

  validUserSession(sessionID, userID, function(err, theUsersSessions){

    if(err === "sessionUnregistered" && theUsersSessions !== null){
      // log.info(processID, moduleName, "UserID exists but session unregistered on Redis");

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

      // log.info(processID, moduleName, "User ID doesn't exist, creating new Redis Hash");
      console.log("addRedisUserSession", "userIDUnregistered");

      registerRedisUserSession({}, sessionID, userID, function (err, reply){

        console.log("registerRedisUserSession", err, reply);

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
      // log.info(processID, moduleName, "REDIS Session Addition for User", userID, sessionID, "already exists"); // Session Exists already!
      if(typeof callBack === "function") callBack("existsAlready", null);
    }
    else{
      // log.error(processID, moduleName, "REDIS Incorrect/Invalid Setting for Redis Session Addition", userID, sessionID); // notValid Input
      if(typeof callBack === "function") callBack("invalid", null);
    }
  });
}

function registerRedisUserSession(theUsersSessions, sessionID, userID, callBack){

  theUsersSessions[sessionID] = {};
  // log.info(processID, moduleName, "REGISTER REDIS SESSION", theUsersSessions);

  ipc.store.hset("userSessions", userID, JSON.stringify(theUsersSessions), function (err, reply){
    // log.info(processID, moduleName, "creating userID", userID, theUsersSessions, err, reply);
    if(typeof callBack === "function") callBack(err, reply);
  });
}


/**
 * Session Info Methods
 */

exports.getRequestSessionInfo = function(sessionID, callBack){

  ipc.store.hget("samsaara:sessions", sessionID, function (err, userID){
    if(typeof callBack === "function") callBack(sessionID, userID);
  });

};


/**
 * Registration Token Methods
 */

exports.generateRegistrationToken = function(connID, callBack){

  var tokenSalt = helper.makeIdAlpha(22);
  var regtoken = helper.makeUniqueHash("sha1", "Registration Key", [connID.toString(), tokenSalt]);

  ipc.store.setex("samsaara:regtoken:" + regtoken, 10, tokenSalt, function (err, reply){
    // log.info(processID, moduleName, "GENERATING REGISTRATION TOKEN FOR", connID, regtoken, tokenSalt, err, reply);
    if(typeof callBack === "function") callBack(null, regtoken);
  });
};

exports.retrieveRegistrationToken = function(regtoken, callBack){
  ipc.store.get("samsaara:regtoken:" + regtoken, function (err, reply){

    // log.info(processID, moduleName, "RETRIEVING REGISTRATION TOKEN", regtoken, err, reply);

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

    console.log(config.uuid, "Auth Store Redis", "VALIDATING REGISTRATION TOKEN FOR", connID, err, reply, tokenSalt);

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
        // log.info(processID, moduleName, "DELETED REGTOKEN:", regtoken, err, reply);
      });
    }
    else{
      if(typeof callBack === "function") callBack(new Error("invalidRegistrationToken"), false);
    }
  });
};
