var SEEK_SET = 0;
var SEEK_END = 2;
var nativeApi = {
	'open': getNativeFunction('open', 'int', ['pointer', 'int']),
	'lseek': getNativeFunction(exportExists('lseek64') ? 'lseek64' : 'lseek', 'int64', ['int', 'int64', 'int']),
	'read': getNativeFunction('read', 'uint64',['int', 'pointer', 'uint64']),
	'close': getNativeFunction('close', 'int', ['int'])
};

function getApplicationContext() {
	var ActivityThread = Java.use('android.app.ActivityThread');
	var app = ActivityThread.currentApplication();
	return app.getApplicationContext();
}

function getNativeFunction(name, returnType, args) {
	return new NativeFunction(Module.findExportByName(null, name), returnType, args);
}

function exportExists(name) {
	return Module.findExportByName(null, name) != null;
}

/* POSIX requires that a file size be printed without a sign, even
   when negative.  Assume the typical case where negative sizes are
   actually positive values that have wrapped around.  */
function unsigned_file_size(size) {
	return size + (size < 0) * (Number.MAX_SAFE_INTEGER - Number.MIN_SAFE_INTEGER + 1);
}


rpc.exports = {
	isFile: function(path) {
		return new Promise(function(resolve) {
			if(Java.available) {
				Java.perform(function () {
					var file = Java.use('java.io.File');
					resolve(file.$new(path).isFile());
				});
			}
			else {
				var isDirectory = Memory.alloc(Process.pointerSize);
				ObjC.classes.NSFileManager.defaultManager().fileExistsAtPath_isDirectory_(path, isDirectory);
				resolve(Memory.readInt(isDirectory) ===  0);
			}
		});
	},
	readFile: function(path, size) {
		var pathStr = Memory.allocUtf8String(path);
		var fd = nativeApi.open(pathStr, 0);
		if (fd === -1)
			throw new Error('error open file');
		var fileSize = nativeApi.lseek(fd, 0, SEEK_END).valueOf();
		fileSize = unsigned_file_size(fileSize);
		nativeApi.lseek(fd, 0, SEEK_SET);
		if(size === 0 || size > fileSize) {
			size = fileSize;
		}

		var buf = Memory.alloc(size);
		var readResult;
		readResult = nativeApi.read(fd, buf, size);

		if (readResult === -1)
			throw new Error('error read');

		nativeApi.close(fd);
		// console.log(buf.readByteArray(size));
		return buf.readByteArray(size);
	},
	fileExists: function(path) {
		return new Promise(function(resolve) {
			if(Java.available) {
				Java.perform(function () {
					var file = Java.use('java.io.File');
					resolve(file.$new(path).exists());
				});
			}
			else {
				resolve(ObjC.classes.NSFileManager.defaultManager().fileExistsAtPath_(path));
			}
		});
	},
	dbQuery: function(path, query) {
		return new Promise(function(resolve) {
			if(Java.available) {
				Java.perform(function () {
					var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
					var result = [];
					var dbHandler = SQLiteDatabase.openDatabase(path, null, 0);
					var cursor = dbHandler.rawQuery(query, null);
					var column_names = cursor.getColumnNames();
					var count = cursor.getCount();
					var i;

					result.push(column_names);
					for (i = 1; i <= count; i++) {
						result.push([]);
					}
					i = 1;
					if (cursor.moveToFirst()) {
						while (!cursor.isAfterLast()) {
							column_names.forEach(function (column) {
								result[i].push(cursor.getString(cursor.getColumnIndex(column)));
							});
							cursor.moveToNext();
							i++;
						}
					}
					resolve(result);
				});
			}
			else {
				// TODO: get the real column names via sqlite3_column_name or any other way
				var dbHandler = SqliteDatabase.open(path);
				var s = dbHandler.prepare(query);
				var row = s.step();
				var flag = false;
				var result = [];
				while(row != null) {
					if(!flag) { // add the columns first
						result.push(Array.from({length: row.length}, (_, i) => "c" + (i +1)));
						flag = true;
					}
					result.push(row.map(item => item)); // TODO: handle ios special objects
					row = s.step();
				}

				resolve(result);
			}
		});
	},
	getPackageInfo: function() {
		return new Promise(function(resolve) {
			if(Java.available) {
				Java.perform(function () {
					var context = getApplicationContext();
					var package_name = context.getPackageName();
					var package_version = context.getPackageManager().getPackageInfo(package_name, 0).versionName.value;
					var resp = {
						'directories': [
							context.getApplicationInfo().sourceDir.value.split("/").slice(0, -1).join("/"),
							context.getDataDir().getAbsolutePath().toString(),
						],
						'package_name': package_name,
						'package_version': package_version,
					};
					for(var i = 0; i < resp.directories.length; i++) {
						var item = Java.use('java.io.File').$new(resp.directories[i]);;
						resp.directories[i] = {
							'isDirectory': item.isDirectory(),
							'isFile': item.isFile(),
							'isHidden': item.isHidden(),
							'lastModified': item.lastModified(),
							'size': item.length(),
							'path': item.getAbsolutePath(),
							'readable': item.canRead(),
							'writeable': item.canWrite(),
							'executable': item.canExecute(),
							'file_type': null
						};
					}
					resolve(resp);
				});
			}
			else {
				var fileManager = ObjC.classes.NSFileManager.defaultManager();
				var info = ObjC.classes.NSBundle.mainBundle().infoDictionary();
				var resp = {
					'directories': [
						ObjC.classes.NSBundle.mainBundle().bundlePath().toString(),
						ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_("HOME").toString(),
					],
					'package_name': info.objectForKey_("CFBundleDisplayName").toString(),
					'package_version': info.objectForKey_("CFBundleShortVersionString").toString()
				};
				for(var i = 0; i < resp.directories.length; i++) {
					var item = fileManager.attributesOfItemAtPath_error_(ObjC.classes.NSURL.fileURLWithPath_(resp.directories[i]).path(), NULL);
					resp.directories[i] = {
						'isDirectory': item.objectForKey_('NSFileType').toString() === 'NSFileTypeDirectory',
						'isFile': item.objectForKey_('NSFileType').toString() === 'NSFileTypeRegular',
						'isHidden': resp.directories[i].toString()[0] === '.',
						'lastModified': Date.parse(item.objectForKey_('NSFileModificationDate').toString()),
						'size': item.objectForKey_('NSFileSize').toString(),
						'path': resp.directories[i],
						'readable': fileManager.isReadableFileAtPath_(resp.directories[i]),
						'writeable': fileManager.isWritableFileAtPath_(resp.directories[i]),
						'executable': fileManager.isExecutableFileAtPath_(resp.directories[i]),
						'file_type': null
					}
				}
				resolve(resp);
			}
		});
	},
	ls: function(path) {
		return new Promise(function (resolve) {
			if(Java.available) {
				Java.perform(function () {
					var resp = {
						'files': [],
						'path': path,
						'readable': false,
						'writeable': false,
					};

					var file = Java.use('java.io.File');
					var directory = file.$new(path);

					resp.readable = directory.canRead();
					resp.writeable = directory.canWrite();
					var files = directory.listFiles();
					files.forEach(function (item) {
						resp.files.push({
							'isDirectory': item.isDirectory(),
							'isFile': item.isFile(),
							'isHidden': item.isHidden(),
							'lastModified': item.lastModified(),
							'size': item.length(),
							'path': item.getAbsolutePath(),
							'readable': item.canRead(),
							'writeable': item.canWrite(),
							'executable': item.canExecute()
						});
					});
					resolve(resp);
				});
			}
			else {
				var resp = {
					'files': [],
					'path': path,
					'readable': false,
					'writeable': false,
				};
				var fileManager = ObjC.classes.NSFileManager.defaultManager();
				var files = fileManager.contentsOfDirectoryAtPath_error_(path, NULL);

				for(var i = 0; i < files.count(); i++) {
					var filepath = [path, files.objectAtIndex_(i)].join('/');
					var attributes = fileManager.attributesOfItemAtPath_error_(ObjC.classes.NSURL.fileURLWithPath_(filepath).path(), NULL);

					resp.files.push({
						'isDirectory': attributes.objectForKey_('NSFileType').toString() === 'NSFileTypeDirectory',
						'isFile': attributes.objectForKey_('NSFileType').toString() === 'NSFileTypeRegular',
						'isHidden': files.objectAtIndex_(i).toString()[0] === '.',
						'lastModified': Date.parse(attributes.objectForKey_('NSFileModificationDate').toString()),
						'size': attributes.objectForKey_('NSFileSize').toString(),
						'path': filepath,
						/* TODO: check with NSFilePosixPermissions */
						'readable': fileManager.isReadableFileAtPath_(filepath),
						'writeable': fileManager.isWritableFileAtPath_(filepath),
						'executable': fileManager.isExecutableFileAtPath_(filepath)
					});
				}

				resolve(resp);
			}
		});
	}
};
