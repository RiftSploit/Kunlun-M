const { exec } = require('child_process');
var cmd = process.argv[2];
exec(cmd, function(err, stdout) {
    console.log(stdout);
});
