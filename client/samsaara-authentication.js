/*!
 * Samsaara Authentication Module
 * Copyright(c) 2014 Arjun Mehta <arjun@newlief.com>
 * MIT Licensed
 */

var samaaraAuthentication = function(options){

  var samsaara, attributes;
  var samsaaraToken = "";

  function updateToken(oldToken, newToken, callBack){
    console.log("UPDATING TOKEN", oldToken, newToken);

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
    // console.log("*******************ATTEMPTING TO LOG IN SESSION");
    samsaara.nsFunc("internal", "requestRegistrationToken", function (err, registrationToken){
      httpGet("/registerSamsaaraConnection?regtoken=" + registrationToken, function (sessionInfo){
        var sessionInfoParsed = JSON.parse(sessionInfo);
        if(sessionInfo.err === undefined){
          samsaara.sessionInfo = {sessionID: sessionInfoParsed.sessionID, userID: sessionInfoParsed.userID};
          samsaara.nsFunc("internal", "login", JSON.parse(sessionInfo), registrationToken);
        // JSON.stringify( [samsaaraOwner, {login: [registrationToken, sessionInfo]}]
        }
      });
    });    
  }

  function initToken(messageObj){
    if(messageObj.samsaaraToken !== undefined){
      samsaaraToken = messageObj.samsaaraToken;
      console.log("Token Received:", samsaaraToken);
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

    samsaara = samsaaraCore;
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