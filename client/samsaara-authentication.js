/*!
 * Samsaara Authentication Module
 *
 * Copyright(c) 2014 Arjun Mehta <arjun@newlief.com>
 * MIT Licensed
 */

var samaaraAuthentication = function(options){

  authenticationDebug = debug('samsaara:authentication');


  var samsaara, attributes;
  var samsaaraToken = "";


  function updateToken(oldToken, newToken, callBack){
    authenticationDebug("UPDATING TOKEN", oldToken, newToken);

    if(samsaaraToken === oldToken){
      samsaara.emitEvent("authenticated", [samsaara.sessionInfo.userID]);
      samsaaraToken = newToken;
      attributes.updateHeaderList("TKN", samsaaraToken);
      if(typeof callBack === "function") callBack(newToken);
    }
    else{
      if(typeof callBack === "function") callBack(false);
    }
  }


  function newConnectionAuthentication(){

    authenticationDebug("*******************ATTEMPTING TO LOG IN SESSION", samsaara.self);

    samsaara.nameSpace("internal").execute("requestRegistrationToken", samsaara.self, function (err, registrationToken){
    
      httpGet("/registerSamsaaraConnection?regtoken=" + registrationToken, function (sessionInfo){
    
        var sessionInfoParsed = JSON.parse(sessionInfo);
    
        if(sessionInfo.err === undefined){
          samsaara.sessionInfo = {sessionID: sessionInfoParsed.sessionID, userID: sessionInfoParsed.userID};
          samsaara.nameSpace("internal").execute("login", samsaara.self, JSON.parse(sessionInfo), registrationToken);        
        }
      });
    });    
  }


  function initToken(messageObj){
    if(messageObj.samsaaraToken !== undefined){
      samsaaraToken = messageObj.samsaaraToken;
      authenticationDebug("Token Received:", samsaaraToken);
      attributes.initializedAttribute("initToken");  
      attributes.updateHeaderList("TKN", samsaaraToken);
    }
  }


  function httpGet(theUrl, callBack){
    var xmlHttp = null;

    xmlHttp = new XMLHttpRequest();
    xmlHttp.open( "GET", theUrl, false );
    xmlHttp.send( null );

    if(callBack) callBack(xmlHttp.responseText);
    else return xmlHttp.responseText;
  }


  return function authentication(samsaaraCore, samsaaraAttributes){

    samsaara = samsaaraCore.samsaara;
    attributes = samsaaraAttributes;

    attributes.force("initToken");

    var exported = {
      
      internalMethods: {
        updateToken: updateToken
      },
      initializationMethods: {
        newConnectionAuthentication: newConnectionAuthentication
      },
      messageRoutes: {
        initToken: initToken
      },
      messageHeaders: {
        TKN: samsaaraToken
      }
    };

    return exported;

  };
};

samsaara.use(samaaraAuthentication());