"""
JAVASCRIPT 内置函数/方法可控性知识库

为静态分析引擎提供该语言内置函数的返回值可控性信息，避免对已知函数进行不必要的函数体分析。

知识条目结构:
    {"函数名": {"passthrough": [参数位置列表], "safe": bool}}

    - passthrough: 返回值依赖哪些参数的位置（0-indexed）。
      [] 表示返回值与输入参数无关（如 len() 返回整数）。
    - safe: True 表示该函数做了有效安全过滤，返回值不再构成安全威胁。
"""
from typing import Dict, List, Optional, Union

# {"函数名": {"passthrough": [参数位置列表], "safe": bool}}
KNOWLEDGE: Dict[str, Dict[str, Union[List[int], bool]]] = {
        # ===== String 方法（透传 this） =====
        "toUpperCase":      {"passthrough": [0], "safe": False},
        "toLowerCase":      {"passthrough": [0], "safe": False},
        "trim":             {"passthrough": [0], "safe": False},
        "trimStart":        {"passthrough": [0], "safe": False},
        "trimEnd":          {"passthrough": [0], "safe": False},
        "trimLeft":         {"passthrough": [0], "safe": False},
        "trimRight":        {"passthrough": [0], "safe": False},
        "replace":          {"passthrough": [0], "safe": False},
        "replaceAll":       {"passthrough": [0], "safe": False},
        "split":            {"passthrough": [0], "safe": False},
        "substring":        {"passthrough": [0], "safe": False},
        "substr":           {"passthrough": [0], "safe": False},
        "slice":            {"passthrough": [0], "safe": False},
        "concat":           {"passthrough": [0], "safe": False},
        "padStart":         {"passthrough": [0], "safe": False},
        "padEnd":           {"passthrough": [0], "safe": False},
        "repeat":           {"passthrough": [0], "safe": False},
        "toString":         {"passthrough": [0], "safe": False},
        "valueOf":          {"passthrough": [0], "safe": False},
        "charAt":           {"passthrough": [0], "safe": False},
        "charCodeAt":       {"passthrough": [], "safe": True},
        "codePointAt":      {"passthrough": [], "safe": True},
        "normalize":        {"passthrough": [0], "safe": False},
        "localeCompare":    {"passthrough": [], "safe": True},
        "match":            {"passthrough": [0], "safe": False},
        "matchAll":         {"passthrough": [0], "safe": False},
        "search":           {"passthrough": [], "safe": True},
        "at":               {"passthrough": [0], "safe": False},
        "fontsize":         {"passthrough": [0], "safe": False},
        "fixed":            {"passthrough": [0], "safe": False},
        "bold":             {"passthrough": [0], "safe": False},
        "italics":          {"passthrough": [0], "safe": False},
        "link":             {"passthrough": [0], "safe": False},

        # ===== Array 方法 =====
        "map":              {"passthrough": [0], "safe": False},
        "filter":           {"passthrough": [0], "safe": False},
        "reduce":           {"passthrough": [0], "safe": False},
        "flat":             {"passthrough": [0], "safe": False},
        "flatMap":          {"passthrough": [0], "safe": False},
        "sort":             {"passthrough": [0], "safe": False},
        "reverse":          {"passthrough": [0], "safe": False},
        "splice":           {"passthrough": [0], "safe": False},
        "slice":            {"passthrough": [0], "safe": False},
        "concat":           {"passthrough": [0], "safe": False},
        "join":             {"passthrough": [0], "safe": False},
        "find":             {"passthrough": [0], "safe": False},
        "findIndex":        {"passthrough": [], "safe": True},
        "indexOf":          {"passthrough": [], "safe": True},
        "lastIndexOf":      {"passthrough": [], "safe": True},
        "includes":         {"passthrough": [], "safe": True},
        "every":            {"passthrough": [], "safe": True},
        "some":             {"passthrough": [], "safe": True},
        "forEach":          {"passthrough": [], "safe": True},
        "push":             {"passthrough": [], "safe": True},
        "pop":              {"passthrough": [0], "safe": False},
        "shift":            {"passthrough": [0], "safe": False},
        "unshift":          {"passthrough": [], "safe": True},
        "fill":             {"passthrough": [0], "safe": False},
        "copyWithin":       {"passthrough": [0], "safe": False},

        # ===== 全局函数 =====
        "String":           {"passthrough": [0], "safe": False},
        "Number":           {"passthrough": [], "safe": True},
        "Boolean":          {"passthrough": [], "safe": True},
        "parseInt":         {"passthrough": [], "safe": True},
        "parseFloat":       {"passthrough": [], "safe": True},
        "isNaN":            {"passthrough": [], "safe": True},
        "isFinite":         {"passthrough": [], "safe": True},
        "Array.from":       {"passthrough": [0], "safe": False},
        "Array.of":         {"passthrough": [0], "safe": False},
        "Object.keys":      {"passthrough": [0], "safe": False},
        "Object.values":    {"passthrough": [0], "safe": False},
        "Object.entries":   {"passthrough": [0], "safe": False},
        "Object.assign":    {"passthrough": [0, 1], "safe": False},
        "Object.create":    {"passthrough": [0], "safe": False},

        # ===== 编解码 =====
        "JSON.stringify":       {"passthrough": [0], "safe": False},
        "JSON.parse":           {"passthrough": [0], "safe": False},
        "encodeURI":            {"passthrough": [0], "safe": False},
        "encodeURIComponent":   {"passthrough": [0], "safe": False},
        "decodeURI":            {"passthrough": [0], "safe": False},
        "decodeURIComponent":   {"passthrough": [0], "safe": False},
        "btoa":                 {"passthrough": [0], "safe": False},
        "atob":                 {"passthrough": [0], "safe": False},
        "escape":               {"passthrough": [0], "safe": False},
        "unescape":             {"passthrough": [0], "safe": False},

        # ===== 安全过滤 =====
        "DOMPurify.sanitize":   {"passthrough": [0], "safe": True},
        "sanitize":             {"passthrough": [0], "safe": True},

        # ===== 不透传 =====
        "length":       {"passthrough": [], "safe": True},
        "typeof":       {"passthrough": [], "safe": True},
        "instanceof":   {"passthrough": [], "safe": True},
        "console.log":  {"passthrough": [], "safe": True},
        "console.warn": {"passthrough": [], "safe": True},
        "console.error": {"passthrough": [], "safe": True},
        "alert":        {"passthrough": [], "safe": True},
        "Math.floor":   {"passthrough": [], "safe": True},
        "Math.ceil":    {"passthrough": [], "safe": True},
        "Math.round":   {"passthrough": [], "safe": True},
        "Math.abs":     {"passthrough": [], "safe": True},
        "Math.max":     {"passthrough": [], "safe": True},
        "Math.min":     {"passthrough": [], "safe": True},
        "Math.random":  {"passthrough": [], "safe": True},

        # ===== Express =====
        "express":              {"passthrough": [], "safe": True},

        # ===== jQuery =====
        "html":                 {"passthrough": [0], "safe": False},
        "append":               {"passthrough": [0], "safe": False},
        "prepend":              {"passthrough": [0], "safe": False},
        "after":                {"passthrough": [0], "safe": False},
        "before":               {"passthrough": [0], "safe": False},
        "replaceWith":          {"passthrough": [0], "safe": False},
        "text":                 {"passthrough": [], "safe": True},
        "attr":                 {"passthrough": [1], "safe": False},
        "val":                  {"passthrough": [0], "safe": False},
        "css":                  {"passthrough": [1], "safe": False},

        # ===== Vue.js =====
        "v-html":               {"passthrough": [0], "safe": False},
        "$createElement":        {"passthrough": [0], "safe": False},

        # ===== React =====
        "dangerouslySetInnerHTML": {"passthrough": [0], "safe": False},

        # ===== template engines =====
        "res.render":           {"passthrough": [0], "safe": False},
        "res.send":             {"passthrough": [0], "safe": False},
        "res.json":             {"passthrough": [0], "safe": False},
        "res.sendFile":         {"passthrough": [0], "safe": False},
        "res.redirect":         {"passthrough": [0], "safe": False},
        "res.write":            {"passthrough": [0], "safe": False},
        "ejs.render":           {"passthrough": [0], "safe": False},
        "ejs.renderFile":       {"passthrough": [0], "safe": False},
        "pug.render":           {"passthrough": [0], "safe": False},
        "handlebars.compile":   {"passthrough": [0], "safe": False},
        "nunjucks.render":      {"passthrough": [0], "safe": False},

        # ===== Angular =====
        "bypassSecurityTrustHtml":        {"passthrough": [0], "safe": False},
        "bypassSecurityTrustStyle":       {"passthrough": [0], "safe": False},
        "bypassSecurityTrustScript":      {"passthrough": [0], "safe": False},
        "bypassSecurityTrustUrl":         {"passthrough": [0], "safe": False},
        "bypassSecurityTrustResourceUrl": {"passthrough": [0], "safe": False},
        "sanitize":                       {"passthrough": [0], "safe": True},
        "DomSanitizer.sanitize":          {"passthrough": [0], "safe": True},
        "DomSanitizer.bypassSecurityTrustHtml":        {"passthrough": [0], "safe": False},
        "DomSanitizer.bypassSecurityTrustStyle":       {"passthrough": [0], "safe": False},
        "DomSanitizer.bypassSecurityTrustScript":      {"passthrough": [0], "safe": False},
        "DomSanitizer.bypassSecurityTrustUrl":         {"passthrough": [0], "safe": False},
        "DomSanitizer.bypassSecurityTrustResourceUrl": {"passthrough": [0], "safe": False},

        # ===== Next.js =====
        "getServerSideProps":  {"passthrough": [0], "safe": False},
        "getStaticProps":      {"passthrough": [0], "safe": False},
        "getStaticPaths":      {"passthrough": [0], "safe": False},
        "getInitialProps":     {"passthrough": [0], "safe": False},
        "NextResponse.json":   {"passthrough": [0], "safe": False},
        "NextResponse.redirect": {"passthrough": [0], "safe": False},
        "NextResponse.rewrite":  {"passthrough": [0], "safe": False},
        "NextRequest.nextUrl":    {"passthrough": [0], "safe": False},
        "NextRequest.cookies":    {"passthrough": [0], "safe": False},
        "NextRequest.searchParams": {"passthrough": [0], "safe": False},

        # ===== NestJS =====
        "Controller":          {"passthrough": [0], "safe": False},
        "Get":                 {"passthrough": [0], "safe": False},
        "Post":                {"passthrough": [0], "safe": False},
        "Put":                 {"passthrough": [0], "safe": False},
        "Delete":              {"passthrough": [0], "safe": False},
        "Patch":               {"passthrough": [0], "safe": False},
        "Body":                {"passthrough": [0], "safe": False},
        "Query":               {"passthrough": [0], "safe": False},
        "Param":               {"passthrough": [0], "safe": False},
        "Headers":             {"passthrough": [0], "safe": False},
        "Req":                 {"passthrough": [0], "safe": False},
        "Res":                 {"passthrough": [0], "safe": False},
        "HttpException":       {"passthrough": [0], "safe": False},
        "HttpStatus":          {"passthrough": [], "safe": True},
        " NestFactory.create": {"passthrough": [0], "safe": False},
        "ValidationPipe":      {"passthrough": [0], "safe": False},

        # ===== Koa =====
        "ctx.body":            {"passthrough": [0], "safe": False},
        "ctx.redirect":        {"passthrough": [0], "safe": False},
        "ctx.render":          {"passthrough": [0], "safe": False},
        "ctx.attachment":      {"passthrough": [0], "safe": False},
        "ctx.set":             {"passthrough": [1], "safe": False},
        "ctx.append":          {"passthrough": [1], "safe": False},
        "ctx.query":           {"passthrough": [0], "safe": False},
        "ctx.params":          {"passthrough": [0], "safe": False},
        "ctx.request.body":    {"passthrough": [0], "safe": False},
        "ctx.request.query":   {"passthrough": [0], "safe": False},
        "ctx.request.header":  {"passthrough": [0], "safe": False},
        "ctx.request.headers": {"passthrough": [0], "safe": False},
        "ctx.throw":           {"passthrough": [0], "safe": False},
        "ctx.type":            {"passthrough": [0], "safe": False},
        "ctx.status":          {"passthrough": [], "safe": True},

        # ===== Lodash =====
        "_.escape":            {"passthrough": [0], "safe": True},
        "_.unescape":          {"passthrough": [0], "safe": False},
        "_.template":          {"passthrough": [0], "safe": False},
        "_.merge":             {"passthrough": [0, 1], "safe": False},
        "_.extend":            {"passthrough": [0, 1], "safe": False},
        "_.assign":            {"passthrough": [0, 1], "safe": False},
        "_.assignIn":          {"passthrough": [0, 1], "safe": False},
        "_.defaults":          {"passthrough": [0, 1], "safe": False},
        "_.defaultsDeep":      {"passthrough": [0, 1], "safe": False},
        "_.clone":             {"passthrough": [0], "safe": False},
        "_.cloneDeep":         {"passthrough": [0], "safe": False},
        "_.pick":              {"passthrough": [0], "safe": False},
        "_.omit":              {"passthrough": [0], "safe": False},
        "_.get":               {"passthrough": [0], "safe": False},
        "_.set":               {"passthrough": [0], "safe": False},
        "_.has":               {"passthrough": [], "safe": True},
        "_.isString":          {"passthrough": [], "safe": True},
        "_.isObject":          {"passthrough": [], "safe": True},
        "_.isArray":           {"passthrough": [], "safe": True},
        "_.isEmpty":           {"passthrough": [], "safe": True},
        "_.trim":              {"passthrough": [0], "safe": False},
        "_.lowerCase":         {"passthrough": [0], "safe": False},
        "_.upperCase":         {"passthrough": [0], "safe": False},
        "_.camelCase":         {"passthrough": [0], "safe": False},
        "_.snakeCase":         {"passthrough": [0], "safe": False},
        "_.kebabCase":         {"passthrough": [0], "safe": False},
        "_.deburr":            {"passthrough": [0], "safe": False},
        "_.truncate":          {"passthrough": [0], "safe": False},
        "_.replace":           {"passthrough": [0], "safe": False},
        "_.split":             {"passthrough": [0], "safe": False},
        "_.join":              {"passthrough": [0], "safe": False},
        "_.sortBy":            {"passthrough": [0], "safe": False},
        "_.groupBy":           {"passthrough": [0], "safe": False},
        "_.flatten":           {"passthrough": [0], "safe": False},
        "_.flattenDeep":       {"passthrough": [0], "safe": False},
        "_.uniqueId":          {"passthrough": [], "safe": True},
        "_.result":            {"passthrough": [0], "safe": False},
        "_.invoke":            {"passthrough": [0], "safe": False},

        # ===== Axios =====
        "axios.get":           {"passthrough": [0], "safe": False},
        "axios.post":          {"passthrough": [0], "safe": False},
        "axios.put":           {"passthrough": [0], "safe": False},
        "axios.delete":        {"passthrough": [0], "safe": False},
        "axios.patch":         {"passthrough": [0], "safe": False},
        "axios.head":          {"passthrough": [0], "safe": False},
        "axios.options":       {"passthrough": [0], "safe": False},
        "axios.request":       {"passthrough": [0], "safe": False},
        "axios.create":        {"passthrough": [], "safe": True},
        "axios.all":           {"passthrough": [0], "safe": False},
        "axios.spread":        {"passthrough": [0], "safe": False},
        "axios.CancelToken":   {"passthrough": [], "safe": True},
        "axios.isCancel":      {"passthrough": [], "safe": True},

        # ===== Node.js: child_process (命令执行) =====
        "child_process.exec":        {"passthrough": [0], "safe": False},
        "child_process.execSync":    {"passthrough": [0], "safe": False},
        "child_process.execFile":    {"passthrough": [0], "safe": False},
        "child_process.execFileSync": {"passthrough": [0], "safe": False},
        "child_process.spawn":       {"passthrough": [0], "safe": False},
        "child_process.spawnSync":   {"passthrough": [0], "safe": False},
        "child_process.fork":        {"passthrough": [0], "safe": False},

        # ===== Node.js: fs (文件系统) =====
        "fs.readFileSync":           {"passthrough": [0], "safe": False},
        "fs.readFile":               {"passthrough": [0], "safe": False},
        "fs.writeFileSync":          {"passthrough": [0], "safe": False},
        "fs.writeFile":              {"passthrough": [0], "safe": False},
        "fs.appendFileSync":         {"passthrough": [0], "safe": False},
        "fs.appendFile":             {"passthrough": [0], "safe": False},
        "fs.unlinkSync":             {"passthrough": [0], "safe": False},
        "fs.unlink":                 {"passthrough": [0], "safe": False},
        "fs.readdirSync":            {"passthrough": [0], "safe": False},
        "fs.readdir":                {"passthrough": [0], "safe": False},
        "fs.statSync":               {"passthrough": [0], "safe": False},
        "fs.stat":                   {"passthrough": [0], "safe": False},
        "fs.existsSync":             {"passthrough": [0], "safe": False},
        "fs.mkdirSync":              {"passthrough": [0], "safe": False},
        "fs.mkdir":                  {"passthrough": [0], "safe": False},
        "fs.rmdirSync":              {"passthrough": [0], "safe": False},
        "fs.rmdir":                  {"passthrough": [0], "safe": False},
        "fs.createReadStream":       {"passthrough": [0], "safe": False},
        "fs.createWriteStream":      {"passthrough": [0], "safe": False},
        "fs.accessSync":             {"passthrough": [0], "safe": False},
        "fs.access":                 {"passthrough": [0], "safe": False},
        "fs.chmodSync":              {"passthrough": [0], "safe": False},
        "fs.chmod":                  {"passthrough": [0], "safe": False},
        "fs.chownSync":              {"passthrough": [0], "safe": False},
        "fs.chown":                  {"passthrough": [0], "safe": False},
        "fs.copyFileSync":           {"passthrough": [0], "safe": False},
        "fs.copyFile":               {"passthrough": [0], "safe": False},
        "fs.openSync":               {"passthrough": [0], "safe": False},
        "fs.open":                   {"passthrough": [0], "safe": False},
        "fs.renameSync":             {"passthrough": [0], "safe": False},
        "fs.rename":                 {"passthrough": [0], "safe": False},
        "fs.lstatSync":              {"passthrough": [0], "safe": False},
        "fs.lstat":                  {"passthrough": [0], "safe": False},
        "fs.readlinkSync":           {"passthrough": [0], "safe": False},
        "fs.readlink":               {"passthrough": [0], "safe": False},
        "fs.symlinkSync":            {"passthrough": [0], "safe": False},
        "fs.symlink":                {"passthrough": [0], "safe": False},
        "fs.unlinkSync":             {"passthrough": [0], "safe": False},
        "fs.realpathSync":           {"passthrough": [0], "safe": False},
        "fs.realpath":               {"passthrough": [0], "safe": False},
        "fs.watch":                  {"passthrough": [0], "safe": False},
        "fs.watchFile":              {"passthrough": [0], "safe": False},

        # ===== Node.js: path =====
        "path.join":                 {"passthrough": [0], "safe": False},
        "path.resolve":              {"passthrough": [0], "safe": False},
        "path.normalize":            {"passthrough": [0], "safe": False},
        "path.basename":             {"passthrough": [0], "safe": False},
        "path.dirname":              {"passthrough": [0], "safe": False},
        "path.extname":              {"passthrough": [0], "safe": False},
        "path.relative":             {"passthrough": [0], "safe": False},
        "path.parse":                {"passthrough": [0], "safe": False},
        "path.format":               {"passthrough": [0], "safe": False},

        # ===== Node.js: http/https (SSRF风险) =====
        "http.get":                  {"passthrough": [0], "safe": False},
        "http.request":              {"passthrough": [0], "safe": False},
        "https.get":                 {"passthrough": [0], "safe": False},
        "https.request":             {"passthrough": [0], "safe": False},
        "http.createServer":         {"passthrough": [0], "safe": False},
        "https.createServer":        {"passthrough": [0], "safe": False},

        # ===== Node.js: crypto =====
        "crypto.createHash":         {"passthrough": [0], "safe": False},
        "crypto.createHmac":         {"passthrough": [0, 1], "safe": False},
        "crypto.createCipher":       {"passthrough": [0, 1], "safe": False},
        "crypto.createDecipher":     {"passthrough": [0, 1], "safe": False},
        "crypto.createCipheriv":     {"passthrough": [0, 1, 2], "safe": False},
        "crypto.createDecipheriv":   {"passthrough": [0, 1, 2], "safe": False},
        "crypto.createSign":         {"passthrough": [0], "safe": False},
        "crypto.createVerify":       {"passthrough": [0], "safe": False},
        "crypto.randomBytes":        {"passthrough": [], "safe": True},
        "crypto.pbkdf2":             {"passthrough": [], "safe": True},
        "crypto.scrypt":             {"passthrough": [], "safe": True},
        "crypto.createDiffieHellman": {"passthrough": [0], "safe": False},

        # ===== Node.js: Buffer =====
        "Buffer.from":               {"passthrough": [0], "safe": False},
        "Buffer.alloc":              {"passthrough": [], "safe": True},
        "Buffer.allocUnsafe":        {"passthrough": [0], "safe": False},
        "Buffer.concat":             {"passthrough": [0], "safe": False},
        "Buffer.allocUnsafeSlow":    {"passthrough": [0], "safe": False},

        # ===== Node.js: net =====
        "net.connect":               {"passthrough": [0], "safe": False},
        "net.createConnection":      {"passthrough": [0], "safe": False},
        "net.createServer":          {"passthrough": [0], "safe": False},

        # ===== Node.js: dns =====
        "dns.lookup":                {"passthrough": [0], "safe": False},
        "dns.resolve":               {"passthrough": [0], "safe": False},
        "dns.reverse":               {"passthrough": [0], "safe": False},

        # ===== Node.js: os =====
        "os.homedir":                {"passthrough": [], "safe": True},
        "os.tmpdir":                 {"passthrough": [], "safe": True},
        "os.hostname":               {"passthrough": [], "safe": True},
        "os.userInfo":               {"passthrough": [], "safe": True},

        # ===== Node.js: stream =====
        "stream.pipe":               {"passthrough": [0], "safe": False},
        "stream.Readable":           {"passthrough": [0], "safe": False},
        "stream.Writable":           {"passthrough": [0], "safe": False},
        "stream.Transform":          {"passthrough": [0], "safe": False},
        "stream.Duplex":             {"passthrough": [0], "safe": False},

        # ===== Node.js: vm (代码执行) =====
        "vm.runInContext":           {"passthrough": [0], "safe": False},
        "vm.runInNewContext":        {"passthrough": [0], "safe": False},
        "vm.runInThisContext":       {"passthrough": [0], "safe": False},
        "vm.compileFunction":        {"passthrough": [0], "safe": False},

        # ===== Node.js: url / querystring =====
        "url.parse":                 {"passthrough": [0], "safe": False},
        "url.format":                {"passthrough": [0], "safe": False},
        "url.resolve":               {"passthrough": [0], "safe": False},
        "querystring.parse":         {"passthrough": [0], "safe": False},
        "querystring.stringify":     {"passthrough": [0], "safe": False},
        "querystring.escape":        {"passthrough": [0], "safe": False},
        "querystring.unescape":      {"passthrough": [0], "safe": False},

        # ===== Node.js: zlib =====
        "zlib.gzip":                 {"passthrough": [0], "safe": False},
        "zlib.gunzip":               {"passthrough": [0], "safe": False},
        "zlib.deflate":              {"passthrough": [0], "safe": False},
        "zlib.inflate":              {"passthrough": [0], "safe": False},
        "zlib.createGzip":           {"passthrough": [0], "safe": False},
        "zlib.createGunzip":         {"passthrough": [0], "safe": False},
        "zlib.createDeflate":        {"passthrough": [0], "safe": False},
        "zlib.createInflate":        {"passthrough": [0], "safe": False},

        # ===== Node.js: process =====
        "process.env":               {"passthrough": [0], "safe": False},
        "process.argv":              {"passthrough": [0], "safe": False},
        "process.cwd":               {"passthrough": [], "safe": True},
        "process.exit":              {"passthrough": [], "safe": True},
        "process.nextTick":          {"passthrough": [], "safe": True},

        # ===== Node.js: eval/Function (代码执行) =====
        "eval":                      {"passthrough": [0], "safe": False},
        "Function":                  {"passthrough": [0], "safe": False},
        "new Function":              {"passthrough": [0], "safe": False},
        "setTimeout":                {"passthrough": [0], "safe": False},
        "setInterval":               {"passthrough": [0], "safe": False},
        "setImmediate":              {"passthrough": [0], "safe": False},

        # ===== Node.js: MongoDB/Mongoose =====
        "mongoose.Query":            {"passthrough": [0], "safe": False},
        "mongoose.Model.find":       {"passthrough": [0], "safe": False},
        "mongoose.Model.findOne":    {"passthrough": [0], "safe": False},
        "mongoose.Model.update":     {"passthrough": [0], "safe": False},
        "mongoose.Model.deleteOne":  {"passthrough": [0], "safe": False},
        "mongoose.Model.deleteMany": {"passthrough": [0], "safe": False},
        "mongoose.Model.aggregate":  {"passthrough": [0], "safe": False},
        "mongoose.Model.where":      {"passthrough": [0], "safe": False},
        "mongoose.Types.ObjectId":   {"passthrough": [0], "safe": False},
        "MongoClient.connect":       {"passthrough": [0], "safe": False},
        "Collection.find":           {"passthrough": [0], "safe": False},
        "Collection.findOne":        {"passthrough": [0], "safe": False},
        "Collection.updateOne":      {"passthrough": [0], "safe": False},
        "Collection.deleteOne":      {"passthrough": [0], "safe": False},
        "Collection.aggregate":      {"passthrough": [0], "safe": False},

        # ===== Node.js: SQL (mysql/pg/sequelize) =====
        "mysql.query":               {"passthrough": [0], "safe": False},
        "mysql.escape":              {"passthrough": [0], "safe": True},
        "mysql.escapeId":            {"passthrough": [0], "safe": True},
        "mysql2.query":              {"passthrough": [0], "safe": False},
        "mysql2.escape":             {"passthrough": [0], "safe": True},
        "pg.query":                  {"passthrough": [0], "safe": False},
        "sequelize.query":           {"passthrough": [0], "safe": False},
        "sequelize.literal":         {"passthrough": [0], "safe": False},
        "sequelize.where":           {"passthrough": [0], "safe": False},
        "knex.raw":                  {"passthrough": [0], "safe": False},
        "knex.whereRaw":             {"passthrough": [0], "safe": False},

        # ===== Node.js: Redis =====
        "redis.get":                 {"passthrough": [0], "safe": False},
        "redis.set":                 {"passthrough": [0], "safe": False},
        "redis.eval":                {"passthrough": [0], "safe": False},
        "redis.evalsha":             {"passthrough": [0], "safe": False},

        # ===== Node.js: XML解析 =====
        "xml2js.parseString":        {"passthrough": [0], "safe": False},
        "libxmljs.parseXml":         {"passthrough": [0], "safe": False},
        "libxmljs.parseHtml":        {"passthrough": [0], "safe": False},
        "fastXmlParser.parse":       {"passthrough": [0], "safe": False},
        "sax.parser":                {"passthrough": [0], "safe": False},

        # ===== Node.js: 模板引擎 (服务端) =====
        "handlebars.compile":        {"passthrough": [0], "safe": False},
        "mustache.render":           {"passthrough": [0], "safe": False},
        "dust.render":               {"passthrough": [0], "safe": False},
        "swig.render":               {"passthrough": [0], "safe": False},
        "doT.template":              {"passthrough": [0], "safe": False},
        "underscore.template":       {"passthrough": [0], "safe": False},

}


def lookup(func_name: str) -> Optional[Dict[str, Union[List[int], bool]]]:
    """
    查询该语言的内置函数知识库

    :param func_name: 函数/方法名
    :return: {"passthrough": [...], "safe": bool} 或 None
    """
    # 精确匹配
    if func_name in KNOWLEDGE:
        return KNOWLEDGE[func_name]

    # 短名匹配（方法名不带类/模块前缀）
    # 如 "html.escape" -> 尝试 "escape"
    if "." in func_name:
        short_name = func_name.split(".")[-1]
        if short_name in KNOWLEDGE:
            return KNOWLEDGE[short_name]

    return None