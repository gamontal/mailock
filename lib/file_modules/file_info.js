var path = require('path');

module.exports = {
  GetFileName: function (filepath) {
    var base_fl_name = path.basename(filepath);
    var filename = base_fl_name.substr(0, base_fl_name.lastIndexOf('.')) || base_fl_name;
    return filename;
  },
  GetExtension: function (filename) {
    var ext = path.extname(filename||'').split('.');
    return ext[ext.length - 1];
  }
};
