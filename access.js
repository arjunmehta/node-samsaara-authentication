/*!
 * samsaara - Context Access Constructor
 * Copyright(c) 2013 Arjun Mehta <arjun@newlief.com>
 * MIT Licensed
 */

exports = module.exports = Access;

/**
 * Access constructore for permissions on an object or function.
 * @constructor
 */
function Access(owner, read, write, readGroups, writeGroups){
  this.owner = owner || true;
  this.read = read || {};
  this.write = write || {};
  this.readGroups = readGroups || {};
  this.writeGroups = writeGroups || {};
}