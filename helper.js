var fs      = require('fs');
var path    = require('path');
var crypto = require('crypto');


//Ontology
exports.validProperty = function (propName, object){
  try{
    return object[propName];
  }
  catch (err){
    return false;
  }
};

exports.existsInArray = function (value, array){
  if(array.indexOf(value) > -1){ return true; }
  else{ return false; }
};

exports.valIndexesOf = function(val, obj){
  var indexes = [];

  for (var index in obj){
    if(!obj.hasOwnProperty(index)) continue;

    if(obj[index] == val){
      indexes.push(index);
    }   
  }

  if(!indexes.length) return false;
  else return indexes;
};

exports.valIndexOf = function(val, obj){
  for (var index in obj){
    if(!obj.hasOwnProperty(index)) continue;

    if(obj[index] == val){
      return index;
    }   
  }
};



//Identity
exports.makeIdAlphaNumerical = function (idLength){
  var text = "";
  var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for( var i=0; i < idLength; i++ ){
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
};

exports.makePseudoRandomID = function(){
  return (Math.random()*10000).toString(36);
};

exports.makeIdAlpha = function (idLength){
  var text = "";
  var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  for( var i=0; i < idLength; i++ ){
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
};

exports.varNameSafe = function (name) {
  return name.replace(/[!\"#$%&'\(\)\*\+,\.\/:;<=> \?\@\[\\\]\^`\{\|\}~]/g, '');
};

exports.pad = function (num, places) {
  var zero = places - num.toString().length + 1;
  return Array(+(zero > 0 && zero)).join("0") + num;
};

exports.makeUniqueHash = function(algorithm, key, salts){

  var hmac = crypto.createHmac(algorithm, key);
  hmac.setEncoding('hex');

  for (var i = 0; i < salts.length; i++) {
    hmac.write(salts[i]);
  }

  hmac.end();
  
  return hmac.read();
};


//Pathology
exports.createNewDir = function (newPath, pathBase, callBack){

  var pathArray = newPath.split("/").filter(function (n){return n;});
  var pathBuild = "";
  var pathLevel = 0;
  var appRoot = path.resolve(pathBase) + "/";

  console.log("PATH ARRAY", pathArray);  

  var _createNewDir = function (pathBuilder){

    pathBuild = pathBuilder + pathArray[pathLevel] + "/";

    fs.stat(appRoot + pathBuild, function (err, stats){
      console.log(appRoot + pathBuild);

      if(err || !stats.isDirectory() ){
        console.log("helper.js 96, fs.stat", err);
        fs.mkdir(appRoot + pathBuild, function (err, thePath){
          console.log("helper.js 96, fs.stat", err, thePath);
          _evalPath();
        });
      }
      else{
        _evalPath();
      }
    });
  };

  var _evalPath = function (){
    pathLevel++;

    if(pathLevel == pathArray.length){
      if(callBack && typeof callBack === "function") callBack(null, appRoot + pathBuild);
    }
    else{
      _createNewDir(pathBuild);
    }
  };

  _createNewDir("");

};



//Chronology
exports.getCurrentTime = function (){
  return new Date().getTime();
};

exports.humanTime = function (ms){

  // var milliseconds  = pad( ms%1000                              , 2);
  // var seconds       = pad( (ms/1000)%60                         , 2);
  // var minutes       = pad( ((milliseconds / (1000*60)) % 60)    , 2);
  // var hours         = pad( ((milliseconds / (1000*60*60)) % 24) , 2);

  // return hours + ":" + minutes + ":" + seconds + ":" + milliseconds;
};



//Statisicology

exports.min = function(arr){
  if (!isArray(arr)) {
    return false;
  }

  var arrMod = [];
  for(var i=0; i<arr.length; i++){
    arrMod.push(arr[i]);
  }

  arrMod.sort(function(a, b) {
    return a - b;
  });

  return arrMod[0];
};


exports.median = function(arr) {
  if (!isArray(arr)) {
    return false;
  }
  
  var arrMod = [];
  for(var i=0; i<arr.length; i++){
    arrMod.push(arr[i]);
  }
  
  arrMod.sort(function(a, b) {
    return a - b;
  });

  var half = Math.floor(arrMod.length / 2);
  if (arrMod.length % 2) return arrMod[half];
  else return (arrMod[half - 1] + arrMod[half]) / 2;
};


function isArray(arr) {
  return Object.prototype.toString.call(arr) === "[object Array]";
}




//Logicology
exports.logToConsole = function(colour){

  var argStart = 0;
  var colourr;

  if(colour == "white" || colour == "yellow" || colour == "blue" || colour == "red" || colour == "green"){
    colourr = colour;
    argStart = 1;
  }
  else
    colourr = "red";
  
    

  var logString = process.pid + " [" + new Date().toTimeString() + "] ";
  
  for(var i=argStart; i<arguments.length; i++)
    logString = logString.concat(JSON.stringify(arguments[i]), " ");

  console.log(logString[colourr]);

};

