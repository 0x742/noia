const frida = require('frida');
const fs = require('fs');
const path = require('path');
const FileType = require('file-type');
const express = require('express');
const bodyParser = require('body-parser');
const Archiver = require('archiver');
const eventEmitter = require("events");
const port = 7421;
const source = fs.readFileSync(path.join(__dirname, 'file-browser.js'), 'utf8');
let session_scripts = {};
const onErrorEmitter = new eventEmitter();

const app = express();
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use('/static', express.static(path.join(__dirname, 'static')));

function errorHandler (err, req, res, next) {
	res.status(500);
	res.render('error', { error: err });
}

app.use(errorHandler);
app.use(bodyParser.json());

app.get('/', async function(req, res) {
	res.render('devices')
});

app.get('/package-home', async function(req, res) {
	res.render('home')
});

app.get('/device/:device/packages', async function(req, res) {
	const device_id = req.params.device;
	res.render('apps', { device_id: device_id })
});

app.get('/device/:device/package/:identifier', async function(req, res) {
	const device_id = req.params.device;
	const identifier = req.params.identifier;
	res.render('package', {device_id: device_id, package: identifier})
});

app.get('/api/devices', async function(req, res) {
	const mgr = await frida.getDeviceManager();
	const list = await mgr.enumerateDevices();
	res.send(list)
});

app.get('/api/device/:device', async function(req, res) {
	const device_id = req.params.device;
	const mgr = await frida.getDeviceManager();
	const list = await mgr.enumerateDevices();
	let device = null;
	list.forEach(function(dev) {
		if(dev.impl.id === device_id) {
			device = dev.impl;
		}
	});
	res.send({"device": device})
});

app.get('/api/device/:device/apps', async function(req, res) {
	let resp = {};
	try {
		const device_id = req.params.device;
		const device = await frida.getDevice(device_id);
		resp = await device.enumerateApplications();
	}
	catch (e) {
		console.error(e);
		resp = {"error": e.message};
	}
	finally {
		res.send(resp)
	}
});

app.post('/api/device/:device/package/:identifier', async function(req, res) {
	const device_id = req.params.device;
	let identifier = req.params.identifier;
	if(!req.body.hasOwnProperty("action")) {
		return res.send({});
	}
	const action = req.body.action;
	let frida_script = null;
	try {
		frida_script = await get_frida_script(device_id, identifier, res);
	}
	catch (e) {
		console.error(e);
		res.send({"error": e.message});
		return;
	}
	let resp = null;
	let errorListener = (message) => {
		if(!resp) // if handle command failed resp is null
			res.send({"error": message});
	};
	onErrorEmitter.once('fridaError', errorListener);
	try {
		resp = await handle_command(device_id, identifier, action, req.body, frida_script);
	}
	catch (e) {
		console.error(e);
		resp = {"error": e.message};
	}
	finally {
		onErrorEmitter.removeListener('fridaError', errorListener);
		res.send(resp)
	}
});

function start() {
	app.listen(port, () =>
		console.log(`noia listening at http://127.0.0.1:${port}/`),
	);
}

function onMessage(message, data) {
	if (message.type === 'send') {
		console.log(message.payload);
	} else if (message.type === 'error') {
		console.error(message.stack);
		onErrorEmitter.emit('fridaError', message.description);
	}
}

function getFilename(path) {
	return path.substring(path.lastIndexOf('/')+1);
}

async function get_frida_script(device_id, package_identifier, res) {
	// handling gadgets
	if(package_identifier === 're.frida.Gadget') {
		package_identifier = 'Gadget';
	}
	// TODO: detect if session expired if so create a new session
	if(!Object.keys(session_scripts).includes(`${device_id}:${package_identifier}`)) {
		const device = await frida.getDevice(device_id);
		let session;
		let pid = -1;
		try {
			session = await device.attach(package_identifier);
		}
		catch(e) {
			pid = await device.spawn(package_identifier);
			session = await device.attach(pid);
		}
		const script = await session.createScript(source);
		script.message.connect(onMessage);
		await script.load();
		if(pid > -1) { // if the application was spawned we should resume it
			device.resume(session.pid);
		}
		session_scripts[`${device_id}:${package_identifier}`] = script;
	}
	else {
		// check if session script is still active
		try {
			let dummy = await session_scripts[`${device_id}:${package_identifier}`].exports.getPackageInfo();
		}
		catch (e) {
			console.error(e);
			console.log(`deleting ${device_id}:${package_identifier} from session_scripts dict because script is destroyed`);
			delete session_scripts[`${device_id}:${package_identifier}`];
			return await get_frida_script(device_id, package_identifier, res);
		}
	}
	return session_scripts[`${device_id}:${package_identifier}`];
}

async function find(ls_func, readFile_func, path, query) {
	let fs = await ls_func(path, true, query);
	let fs_files_new = [];
	for (let file of fs.files) {
		file["file_type"] = null;
		if (file.isFile && file.size > 0 && file.path && getFilename(file.path).includes(query)) {
			file["file_type"] = "data";
			if(readFile_func !== null) {
				let fileContent = await readFile_func(file.path, 0x100); // partly read for detecting file type
				let file_type = await FileType.fromBuffer(new Uint8Array(fileContent));
				if (file_type !== undefined) {
					file["file_type"] = file_type.mime.startsWith("image") ? file_type.mime : file_type.ext;
				}
			}
			else {
				file["file_type"] = null;
			}
			fs_files_new.push(file);
		}
		if(file.isDirectory) {
			let recursiveLsResult = await find(ls_func, readFile_func, `${file.path}`, getFilename(file.path).includes(query) ? "" : query);
			fs_files_new = fs_files_new.concat(recursiveLsResult);
		}
	}
	return fs_files_new;
}

async function handle_command(device_id, identifier, action, params, frida_script) {
	let resp = {};
	if (action === "package_info") {
		resp = await frida_script.exports.getPackageInfo();
	} else if (action === "ls") {
		if (!params.hasOwnProperty("path")) {
			return {"error": "invalid params"};
		}
		let path = params.path;
		let fs = await frida_script.exports.ls(path);
		let fs_files_new = [];
		for (let file of fs.files) {
			file["file_type"] = null;
			if (file.isFile && file.size > 0) {
				file["file_type"] = "data";
				let fileContent = await frida_script.exports.readFile(file.path, 0x100); // partly read for detecting file type
				let	file_type = await FileType.fromBuffer(fileContent);
				if (file_type !== undefined) {
					file["file_type"] = file_type.mime.startsWith("image") ? file_type.mime : file_type.ext;
				}
			} else if (file.isFile && file.size == 0) {
				file["file_type"] = "empty";
			}
			fs_files_new.push(file);
		}
		resp = fs_files_new;
	} else if (action === "find") {
		if (!params.hasOwnProperty("path") && !params.hasOwnProperty("query")) {
			return {"error": "invalid params"};
		}
		const path = params.path;
		const query = params.query;
		resp = await find(frida_script.exports.ls, frida_script.exports.readFile, path, query);
	} else if (action === "read") {
		if (!params.hasOwnProperty("path")) {
			return {};
		}
		const path = params.path;
		if (!(await frida_script.exports.fileExists(path))) {
			return {"error": "invalid file path"};
		}
		if (await frida_script.exports.isFile(path)) {
			const fileContent = await frida_script.exports.readFile(path, 0);
			let file_type = await FileType.fromBuffer(fileContent);
			if (file_type !== undefined) {
				file_type = file_type.ext;
			}
			resp = {
				"filename": getFilename(path),
				"type": file_type,
				"content": new TextDecoder("utf-8").decode(fileContent)
				// RangeError: Maximum call stack size exceeded
				// "content": String.fromCharCode.apply(null, fileContent)
			}
		} else {
			async function archiveDirectory(path) {
				return new Promise(async function (resolve) {
					const zip = Archiver('zip');
					var tmp = require('os').tmpdir();
					var destination = tmp + '/' + Date.now() + '.zip';
					var destinationStream = fs.createWriteStream(destination);
					zip.pipe(destinationStream).on('close', async function () {
						console.log(destination);
						let fileContent = await fs.readFileSync(destination);
						await fs.unlinkSync(destination);
						resolve({
							"filename": `${getFilename(path)}.zip`,
							"type": "zip",
							"content": String.fromCharCode.apply(null, fileContent)
						});
					});
					let dir_tree = await find(frida_script.exports.ls, null, path, '', false);
					for (const item of dir_tree) {
						let fileContent = await frida_script.exports.readFile(item.path, 0);
						console.log(`appending ${item.path.substring(path.length + 1)}`);
						zip.append(Buffer.from(fileContent), {'name': item.path.substring(path.length + 1)});
					}
					zip.finalize();
				});
			}

			await archiveDirectory(path).then(res => {
				resp = res;
			});
		}
	} else if (action === "database") {
		if (!params.hasOwnProperty("path") && !params.hasOwnProperty("query")) {
			return {"error": "invalid params"};
		}
		const path = params.path;
		const query = params.query;
		resp = await frida_script.exports.dbQuery(path, query);
	}
	return resp;
}

module.exports = {
	app,
	start,
};

if (!module.parent) {
	start();
}