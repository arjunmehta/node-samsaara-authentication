var authentication = require('./authentication');
var sessions = authentication.sessions;
var userSessions = authentication.userSessions;


var path = require("path");
var log = require("./log.js");
var moduleName = path.basename(module.filename);
var processID = process.pid.toString();
var helper = require("./helper.js");
var config = require("./config.js");


var regTokens = {};

exports = module.exports;

/**
 * User Session Methods
 */

var validUserSession = exports.validUserSession = function(sessionID, userID, callBack){

  if(sessionID !== undefined && userID !== undefined){

    if(userSessions[userID] !== undefined){
      console.log("USER SESSIONS", userID, userSessions[userID]);
      var theUsersSessions = userSessions[userID].activeSessions;

      if(theUsersSessions[sessionID] !== undefined){
        if(typeof callBack === "function") callBack(null, theUsersSessions);
      }
      else{
        if(typeof callBack === "function") callBack("sessionUnregistered", theUsersSessions);
      }
    }
    else{
      if(typeof callBack === "function") callBack("0", null);
    }
  }
  else{
    if(typeof callBack === "function") callBack("Incorrect number of Parameters", null);
  }

};

exports.addUserSession = function (sessionID, userID, callBack){
    sessions[sessionID] = userID;

    if(userSessions[userID] === undefined){
      userSessions[userID] = { activeSessions: {} };
      userSessions[userID].activeSessions[sessionID] = true;
    }
    else{
      userSessions[userID].activeSessions[sessionID] = true;
    }

    if(typeof callBack === "function") callBack (null, true);
};

exports.removeUserSession = function(sessionID, userID, callBack){

  delete sessions[sessionID];
  delete userSessions[userID].activeSessions[sessionID];

  if(Object.keys(userSessions[userID].activeSessions).length === 0){
    delete userSessions[userID];
  }
};

exports.updateUserSession = function(userID, usersSessions, callBack){
  userSessions[userID].activeSessions = usersSessions;
  if(typeof callBack === "function") callBack(null, userSessions);
};

exports.addNewConnectionSession = function(connID, userID, sessionID, usersSessions, callBack){
  usersSessions[sessionID][connID] = 1;
  userSessions[userID].activeSessions = usersSessions;
  if(typeof callBack === "function") callBack(null, userSessions);
};


/**
 * Session Info Methods
 */

exports.getRequestSessionInfo = function(sessionID, callBack){
  if(typeof callBack === "function") callBack(sessionID, sessions[sessionID]);
};



/**
 * Registration Token Methods
 */

exports.generateRegistrationToken = function(connID, callBack){

  var tokenSalt = helper.makeIdAlpha(22);
  var regtoken = helper.makeUniqueHash("sha1", "Registration Key", [connID.toString(), tokenSalt]);
  
  setRegToken("samsaara:regtoken:" + regtoken, tokenSalt);
  if(typeof callBack === "function") callBack(null, regtoken);
};

exports.retrieveRegistrationToken = function(regtoken, callBack){
  var tokenReply = getRegToken("samsaara:regtoken:" + regtoken);
  if(typeof callBack === "function") callBack(null, tokenReply);
};

exports.validateRegistrationToken = function(connID, regtoken, tokenSalt, callBack){

  var tokenReply = getRegToken("samsaara:regtoken:" + regtoken);

  if(tokenReply === tokenSalt){
    var regtokenGen = helper.makeUniqueHash("sha1", "Registration Key", [connID.toString(), tokenSalt]);

    if(regtokenGen === regtoken){
      if(typeof callBack === "function") callBack(null, true);
    }
    else{
      if(typeof callBack === "function") callBack("tokenMismatch", false);
    }
  }
  else if(tokenReply !== null && tokenReply !== tokenSalt){
    if(typeof callBack === "function") callBack("tokenKeyMismatch", false);
  }
  else{
    if(typeof callBack === "function") callBack("invalidRegistrationToken", false);
  }

  delete regTokens[tokenString];    
};

var tokenRequestCounter = 0;
function getRegToken(tokenString){
  var tokenReply = regTokens[tokenString].tokenValue;
  tokenRequestCounter++;
  if(tokenRequestCounter >= 2000){
    clearExpiredTokens();
  }
  return tokenReply;  
}

function setRegToken(tokenString, tokenValue){
  regTokens[tokenString] = new RegToken(tokenValue);
}

function clearExpiredTokens(){
  var currentTime = new Date().getTime();
  for(var tokenString in regTokens){
    if(currentTime > regTokens[tokenString].expiry){
      delete regTokens[tokenString];
    }
  }
}

var RegToken = function(tokenValue){
  this._tokenValue = tokenValue;
  this.expiry = new Date().getTime() + 10000;
};

Object.defineProperty(RegToken.prototype, 'tokenValue', {
    get: function() {
      if(new Date().getTime() < this.expiry){
        return this._tokenValue;
      }
      else{
        return null;
      }
    },
    set: function(tokenValue) {
      this._tokenValue = tokenValue;
    }
});

