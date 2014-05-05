/*!
 * Samsaara - authentication Methods
 * Copyright(c) 2013 Arjun Mehta <arjun@newlief.com>
 * MIT Licensed
 */

exports = module.exports = new Authentication();

var path = require("path");
var log = require("./log.js");
var moduleName = path.basename(module.filename);
var processID = process.pid.toString();

var helper = require("./helper.js");
var config = require("./config.js");

var samsaara = ('../index.js');
var connectionController = require("./connectionController.js");

var authentication,
    authStore;

var sessions, userSessions;

function Authentication(){
  authentication = this;
  this.userSessions = userSessions = {};
  this.sessions = sessions = {};
}

function loginConnection(connection, messageObj){

  var loginObject = JSON.parse(messageObj.login[1]) || null;
  var regTokenSalt = loginObject.tokenKey || null;
  var regToken = messageObj.login[0] || null;

  log.info(process.pid, moduleName, "messageObj.login", messageObj.login, loginObject);

  authentication.validateRegistrationToken(connection.id, regToken, regTokenSalt, function (err, reply){
    if(err === null){

      connection.navInfo.sessionInfo = loginObject;

      log.info(process.pid, moduleName, "RECEIVING REQUEST TO LOGIN Samsaara CONNECTION", loginObject);

      // generates a new token for the connection.
      // integrated check for session validity.
      authentication.initiateUserToken( connectionController.connections[connection.id], loginObject.sessionID, loginObject.userID, function (err, token, userID){

        if(err !== null){
          log.error(process.pid, moduleName, "TOKEN ASSIGNMENT ERROR", err);
          sendToClient( connection.id, { internal: "reportError", args: [187, err, "Invalid Token Initiation: Session either Expired or Invalid"] });
        }
        else if(err === null && userID === loginObject.userID){

          log.info(process.pid, moduleName, "SENDING TOKEN TO", connection.id, userID, token);
          config.emit("connectionLoggedIn", connection, loginObject);

          sendToClient( connection.id, { internal: "updateToken", args: [connection.oldToken, token]}, function (token){
            // 'this' is now the one returning the callBack.
            log.info(process.pid, moduleName, "DELETING OLD TOKEN for", this.id, this.oldToken, token);
            this.oldToken = null;
          });
        }
      });
    }
    else{
      log.error(process.pid, moduleName, "CONNECTION LOGIN ERROR:", err);
    }
  });
}

Authentication.prototype.setRedisStore = function(){
  if(config.redisStore === true){
    authStore = require('./authentication-redis');
  }
  else{
    authStore = require('./authentication-memory');
  }

  this.exported = {
    addUserSession: authStore.addUserSession,
    removeUserSession: authStore.removeUserSession
  };

  this.getRequestSessionInfo = authStore.getRequestSessionInfo;
  this.retrieveRegistrationToken = authStore.retrieveRegistrationToken;
  this.validateRegistrationToken = authStore.validateRegistrationToken;
};

Authentication.prototype.initiateUserToken = function(conn, sessionID, userID, callBack){

  // console.log("INITIATING USER TOKEN", conn.id, sessionID, userID);

  authStore.validUserSession(sessionID, userID, function (err, userSessions){

    // console.log("validUserSession", sessionID, userID);

    if(err === null && userSessions !== undefined){

      authStore.addNewConnectionSession(conn.id, userID, sessionID, userSessions, function (err, userSessions){

        // console.log("addNewConnectionSession", userSessions);

        if(err === null){
          updateConnectionUserID(conn, userID, function (token, userID){
            if(typeof callBack === "function") callBack(err, token, userID);
          });
        }
        else{
          if(typeof callBack === "function") callBack(err, null, null);
        }
      });
    }
    else{
      if(typeof callBack === "function") callBack(err, null, null);
    }
  });
};

Authentication.prototype.requestRegistrationToken = function(callBack){

  console.log(processID, moduleName, "CLIENT, requesting login Token", this.id);

  authStore.generateRegistrationToken(this.id, function (err, regtoken){
    if(typeof callBack === "function") callBack(err, regtoken);
  });

};


Authentication.prototype.removeConnectionSession = function(connID, callBack){

  var conn = connectionController.connections[connID];

  if(conn !== undefined && conn.navInfo !== undefined && conn.navInfo.sessionInfo !== undefined){

    var userID = conn.navInfo.sessionInfo.userID;
    var sessionID = conn.navInfo.sessionInfo.sessionID;

    authStore.validUserSession(sessionID, userID, function (err, userSessions){

      if(!err && userSessions !== undefined && userSessions[sessionID] !== undefined){
        delete userSessions[sessionID][connID];
        authStore.updateUserSession(userID, userSessions, callBack);        
      }
      else{
        if(typeof callBack === "function") callBack("sessionID doesn't exist in UserSessions for UserID", false);
      }

    });
  }
  else{
    if(typeof callBack === "function") callBack("sessionInfo not found on connection", false);
  }
};


function updateConnectionUserID (conn, userID, callBack){
  conn.userID = userID;
  conn.oldToken = conn.token;
  conn.token = helper.makeUniqueHash('sha1', conn.key, [conn.userID]);
  if(typeof callBack === "function") callBack(conn.token, userID);
}


Authentication.prototype.getConnectionSessionInfo = function(connection, callBack){
  var sessionInfo = connection.navInfo.sessionInfo || {};
  sessionID = sessionInfo.sessionID || ("anon" + helper.makeIdAlpha(15));
  userID = sessionInfo.userID || ("userID" + helper.makeIdAlpha(15));
  if(typeof callBack === "function") callBack(sessionID, userID);
};

// Authentication.prototype.addConnectionToUser = function(reqType, source, callBack){

//   //Ontological Existence in Various Contexts

//   if(reqType == "direct"){
//     var userID = source.userID;
//     var connID = source.connID;
//     authentication.userSessions[userID].openConnections[connID] = true;
//     log.info(processID, moduleName, "EXECUTING add CONNECTION TO USER");
//     if(typeof callBack === "function") callBack(connID + " Added to UserSessions on " + processID);
//   }
//   else{
//     userSessionExists(reqType, source, function(exists, userName, sessionID, userID){

//       if(reqType == "connection"){

//         var connection = source.connection;

//         if(exists == "local"){
//           authentication.userSessions[userID].openConnections[connection.id] = true;
//           if(typeof callBack === "function") callBack(connection.id + " Added to UserSessions on " + processID);
//         }
//         else if(exists == "foreign"){
//           communication.sendToForeign("User", userID, {func: "addConnectionToUser", args: ["direct", {userID: userID, connID: connection.id}], specialKey: config.specialKey }, callBack);
//         }
//         else{
//           //log.info(processID, moduleName, "USER NOT LOGGED IN, LOGIN USER");
//           if(typeof callBack === "function") callBack("USER NOT LOGGED IN " + processID);
//         }
//       }
//     });
//   }
// };


function userSessionExists(userID, source, callBack){

  if(userSessions[userID]){
    if(typeof callBack === "function") callBack(true, "local");
  }
  else{
    if(config.redisStore === true){
      config.redisClient.hexists("userSessions", userID, function(err, reply){
        if(reply == 1){
          if(typeof callBack === "function") callBack(true, "foreign");
        }
        else{
          if(typeof callBack === "function") callBack(false, false);
        }
      });
    }
    else{
      if(typeof callBack === "function") callBack(false, false);
    }
  }
}
