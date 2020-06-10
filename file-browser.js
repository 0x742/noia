var SEEK_SET = 0;
var SEEK_END = 2;
var nativeApi = {
	'open': getNativeFunction('open', 'int', ['pointer', 'int']),
	'lseek': getNativeFunction('lseek', 'int64', ['int', 'int64', 'int']),
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

rpc.exports = {
	isFile: function(path) {
		return new Promise(function(resolve) {
			Java.perform(function() {
				var file = Java.use('java.io.File');
				resolve(file.$new(path).isFile());
			});
		});
	},
	readFile: function(path, size) {
		var pathStr = Memory.allocUtf8String(path);
		var fd = nativeApi.open(pathStr, 0);
		if (fd === -1)
			throw new Error('error open file');

		var fileSize = nativeApi.lseek(fd, 0, SEEK_END).valueOf();
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
			Java.perform(function() {
				var file = Java.use('java.io.File');
				resolve(file.$new(path).exists());
			});
		});
	},
	dbQuery: function(path, query) {
		return new Promise(function(resolve) {
			Java.perform(function() {
				var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
				var result = [];
				var dbHandler = SQLiteDatabase.openDatabase(path, null, 0);
				var cursor = dbHandler.rawQuery(query, null);
				var column_names = cursor.getColumnNames();
				var count = cursor.getCount();
				var i;

				result.push(column_names);
				for(i = 1; i <= count; i++) {
					result.push([]);
				}
				i = 1;
				if (cursor.moveToFirst()) {
					while (!cursor.isAfterLast()) {
						column_names.forEach(function(column) {
							result[i].push(cursor.getString(cursor.getColumnIndex(column)));
						});
						cursor.moveToNext();
						i++;
					}
				}
				resolve(result);
			});
		});
	},
	getPackageInfo: function() {
		return new Promise(function(resolve) {
			Java.perform(function() {
				var context = getApplicationContext();
				var package_name = context.getPackageName();
				var package_version = context.getPackageManager().getPackageInfo(package_name, 0).versionName.value;
				var resp = {
					'data_directory': context.getDataDir().getAbsolutePath().toString(),
					'files_directory': context.getFilesDir().getAbsolutePath().toString(),
					'package_name': package_name,
					'package_version': package_version,
				};
				resolve(resp);
			});
		});
	},
	ls: function(path) {
		return new Promise(function (resolve) {
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
		});
	}
};
