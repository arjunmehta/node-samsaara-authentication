/*!
 * Samsaara Authentication Module
 * Copyright(c) 2014 Arjun Mehta <arjun@newlief.com>
 * MIT Licensed
 */

var debug = require('debug')('samsaara:authentication');
var helper = require('./helper');

function authentication(options){

  var config,
      connectionController,
      communication,
      ipc,
      authStore,
      samsaara;

  var addUserSession,
      removeUserSession,
      getRequestSessionInfo,
      retrieveRegistrationToken,
      validateRegistrationToken;

  var sessions = {}; // holds sessions associated with userID ie: sessions[sessionID] = userID;
  var userSessions = {}; // holds all sessions associated with a userID ie. userSessions.activeSessions[userID] = {sessionID1: true, sessionID2: true}


  /**
   * Foundation Methods
   */


  function requestRegistrationToken(callBack){

    debug("Request Registration Token", config.uuid, "Authentication", "CLIENT, requesting login Token", this.connection.id);

    authStore.generateRegistrationToken(this.connection.id, function (err, regtoken){
      if(typeof callBack === "function") callBack(err, regtoken);
    });
  }

  function loginConnection(loginObject, regToken){

    debug("Logging in Connection", this.connection.id, loginObject, regToken);

    var connection = this.connection;
    var regTokenSalt = loginObject.tokenKey || null;
    // var regToken = messageObj.login[0] || null;

    // log.info(process.pid, moduleName, "messageObj.login", loginObject, regToken, regTokenSalt);

    authStore.validateRegistrationToken(connection.id, regToken, regTokenSalt, function (err, reply){

      debug("Validate Registration Token", connection.id, err, reply, loginObject, regToken);

      if(err === null){

        connection.sessionInfo = loginObject;

        // log.info(process.pid, moduleName, "RECEIVING REQUEST TO LOGIN Samsaara CONNECTION", loginObject);

        // generates a new token for the connection.
        // integrated check for session validity.
        initiateUserToken( connectionController.connections[connection.id], loginObject.sessionID, loginObject.userID, function (err, token, userID){

          if(err !== null){
            // log.error(process.pid, moduleName, "TOKEN ASSIGNMENT ERROR", err);
            communication.sendToClient( connection.id, { internal: "reportError", args: [187, err, "Invalid Token Initiation: Session either Expired or Invalid"] });
          }
          else if(err === null && userID === loginObject.userID){
            // log.info(process.pid, moduleName, "SENDING TOKEN TO", connection.id, userID, token);
            samsaara.emit("connectionLoggedIn", connection, loginObject);
            communication.sendToClient( connection.id, { internal: "updateToken", args: [connection.oldToken, token]}, function (token){
              connection.oldToken = null;
            });
          }
        });
      }
      else{
        // log.error(process.pid, moduleName, "CONNECTION LOGIN ERROR:", err);
      }
    });
  }


  function initiateUserToken(conn, sessionID, userID, callBack){

    // debug("INITIATING USER TOKEN", conn.id, sessionID, userID);

    authStore.validUserSession(sessionID, userID, function (err, userSessions){

      // debug("validUserSession", sessionID, userID);

      if(err === null && userSessions !== undefined){

        authStore.addNewConnectionSession(conn.id, userID, sessionID, userSessions, function (err, userSessions){

          // debug("addNewConnectionSession", userSessions);

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
  }

  function removeConnectionSession(connID, callBack){

    var connection = connectionController.connections[connID];

    if(connection !== undefined && connection.sessionInfo !== undefined){

      var userID = connection.sessionInfo.userID;
      var sessionID = connection.sessionInfo.sessionID;

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
  }


  function updateConnectionUserID (connection, userID, callBack){
    connection.userID = userID;
    connection.oldToken = connection.token;
    connection.token = helper.makeUniqueHash('sha1', connection.key, [connection.userID]);
    if(typeof callBack === "function") callBack(connection.token, userID);
  }





  function getConnectionSessionInfo(connection, callBack){
    var sessionInfo = connection.sessionInfo || {};
    sessionID = sessionInfo.sessionID || ("anon" + helper.makeIdAlpha(15));
    userID = sessionInfo.userID || ("userID" + helper.makeIdAlpha(15));
    if(typeof callBack === "function") callBack(sessionID, userID);
  }


  function userSessionExists(userID, source, callBack){

    if(userSessions[userID]){
      if(typeof callBack === "function") callBack(true, "local");
    }
    else{
      if(config.interProcess === true){
        ipc.store.hexists("userSessions", userID, function(err, reply){
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






  function connectionPreInitialization(connection){

    connection.userID = 'anonymous' + helper.makePseudoRandomID();
    connection.key = helper.makePseudoRandomID() + connection.id;
    connection.token = helper.makeUniqueHash('sha1', connection.key, [connection.userID]);

    connection.write(JSON.stringify(["initToken",{
      samsaaraToken: connection.token
    }]));

  }

  /**
   * Connection Initialization Method
   * Called for every new connection
   *
   * @opts: {Object} contains the connection's options
   * @connection: {SamsaaraConnection} the connection that is initializing
   * @attributes: {Attributes} The attributes of the SamsaaraConnection and its methods
   */

  function connectionInitialzation(opts, connection, attributes){

    if(opts.session !== undefined){
      debug("Initializing Authentication...", opts.session, connection.id);
      attributes.force("authentication");
      attributes.initialized(null, "authentication");
    }
  }


  function connectionClosing(connection){
    removeConnectionSession(connection.id);
  }


  function preRouteAuthentication(connection, owner, messageAttributes, newPrepend, message, next){
    var token = messageAttributes[messageAttributes.indexOf("TKN")+1];
    if(token === connection.token || token === connection.oldToken){
      next();
    }
    else{
      next("Invalid Token");
    }
  }


  /**
   * Module Return Function.
   * Within this function you should set up and return your samsaara middleWare exported
   * object. Your eported object can contain:
   * name, foundation, remoteMethods, connectionInitialization, connectionClose
   */

  return function authentication(samsaaraCore){

    // debug(samsaaraCore,);
    samsaara = samsaaraCore;
    config = samsaaraCore.config;
    connectionController = samsaaraCore.connectionController;
    communication = samsaaraCore.communication;
    ipc = samsaaraCore.ipcRedis;


    if(config.interProcess === true){
      authStore = require('./authentication-redis');
      authStore.initialize(config, ipc);
    }
    else{
      authStore = require('./authentication-memory');
      authStore.initialize(config, sessions, userSessions);
    }

    addUserSession = authStore.addUserSession;
    removeUserSession = authStore.removeUserSession;

    getRequestSessionInfo = authStore.getRequestSessionInfo;
    retrieveRegistrationToken = authStore.retrieveRegistrationToken;
    validateRegistrationToken = authStore.validateRegistrationToken;


    samsaaraCore.addClientGetRoute('/registerSamsaaraConnection', function (req, res){

      var registrationToken = req.query.regtoken;

      retrieveRegistrationToken(registrationToken, function (err, reply){
        if(err === null){
          
          getRequestSessionInfo(req.sessionID, function (sessionID, userID){              
            var keyObject = { sessionID: sessionID, userID: userID, tokenKey: reply };
            res.send(keyObject);
          });
        }
        else{
          res.send({ err: err });
        }
      });
    });

    samsaaraCore.addClientFileRoute("samsaara-authentication.js", __dirname + '/client/samsaara-authentication.js');

    var exported = {

      name: "authentication",

      clientScript: __dirname + '/client/samsaara-authentication.js', 

      foundationMethods: {
        addUserSession: addUserSession,
        removeUserSession: removeUserSession
      },

      remoteMethods: {
        login: loginConnection,
        requestRegistrationToken: requestRegistrationToken
      },

      connectionPreInitialization: {
        authentication: connectionPreInitialization
      },

      connectionInitialization: {
        authentication: connectionInitialzation
      },

      connectionClose: {
        authentication: connectionClosing        
      },

      preRouteFilters:{}
    };

    if(options.strict === true){
      exported.preRouteFilters.preRouteAuthentication = preRouteAuthentication;
    }

    return exported;

  };

}

module.exports = exports = authentication;
