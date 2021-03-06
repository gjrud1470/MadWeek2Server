// Import package
var mongodb = require('mongodb');
var ObjectID = mongodb.ObjectID;
var crypto = require('crypto');
var express = require('express');
var bodyParser = require('body-parser');
var path = require('path');
var multer = require('multer');
var fs = require('fs');


var storage = multer.diskStorage({
    destination: function(req, file, cb) {
      cb(null, 'uploads')
    },
    filename: function(req, file, cb) {
      cb(null, file.fieldname + '_' + Date.now() + path.extname(file.originalname))
    }
  });
  
var upload = multer({
    storage: storage
});

function base64_encode(file) {
    // read binary data
    var bitmap = fs.readFileSync(file);
    // convert binary data to base64 encoded string
    return new Buffer(bitmap).toString('base64');
}

//PASSWORD UTILS
//CREATE FUNCTION TO RANDOM SALT
var genRamdomString = function (length) {
	return crypto.randomBytes(Math.ceil(length/2))
		.toString('hex')
		.slice(0, length);
};

var sha512 = function (password, salt){
	var hash = crypto.createHmac ('sha512',salt);
	hash.update(password);
	var value = hash.digest('hex');
	return {
		salt:salt,
		passwordHash:value
	};
};

function saltHashPassword (userPassword) {  
	var salt = genRamdomString(16);
	var passwordData = sha512(userPassword, salt);
	return passwordData;
}

function checkHashPassword (userPassword, salt){
	var password = sha512(userPassword, salt);
	return password;
}

// Create Express service       

var app = express();
app.use(bodyParser.json({limit:'500mb'}));
app.use(bodyParser.urlencoded({ limit: '500mb', extended: true}));
app.use(express.static('public'));

// Create MongoDB Client
var MongoClient = mongodb.MongoClient;

// Connection URL
var url = 'mongodb://127.0.0.1:27017'

MongoClient.connect (url, {useNewUrlParser: true}, function (err,client){
	if (err)
		console.log('Unable to connect to the mongoDB server.Error', err);
	else{

        //Register
        app.post('/register', (request, response, next)=> {
            var post_data = request.body;
            
            var plaint_password = post_data.password;
            var hash_data = saltHashPassword(plaint_password);

            var password = hash_data.passwordHash;
            var salt = hash_data.salt;
            
            var name = post_data.name;
            var email = post_data.email;

            var insertJson = {
                'email' : email,
                'password' : password,
                'salt' : salt,
                'name' : name
            };
            var db = client.db('Ku');

            // Check exists email
            db.collection('user')
                .find({'email':email}).count(function(err,number){
                    if(number != 0){
                        response.json('Email already exists');
                        console.log(email);
                    }
                    else{
                        // Insert Data
                        db.collection('user')
                            .insertOne(insertJson, function(error, res){
                                response.json('Registration success');
                                console.log('Registration success');
                            })
                    }
                })
        });

        app.post('/login', (request, response, next)=> {
            var post_data = request.body;

            var email = post_data.email;
            var userPassword = post_data.password;

            var db = client.db('Ku');

            // Check exists email
            db.collection('user')
                .find({'email':email}).count(function(err,number){
                    if(number == 0){
                        response.json({login_success:'fail'});
                        console.log(email);
                    }
                    else{

                        // Insert Data
                        db.collection('user')
                            .findOne({'email':email}, function(err,user){
                                var salt = user.salt; // Get salt from user
                                var hashed_password = checkHashPassword(userPassword, salt).passwordHash;
                                var encrypted_password = user.password;
                                if (hashed_password == encrypted_password){
                                    response.json({login_success : 'success',
						   salt : salt});
                                    console.log("Login success");
                                }
                                else{
                                    response.json({login_success : 'fail'});
                                    console.log("Wrong success");
                                }
                            })
                    }
                })
        });

	app.post('/pre-login', (request, response, next)=> {
		var post_data = request.body;

		var salt = post_data.salt;

		var db = client.db('Ku');

		db.collection('user')
			.find({salt:salt}).count(function(err,number){
				if(number == 0){
					response.json({login_success: 'fail'});
					console.log("Pre-login fail");
				}
				else{
					response.json({login_success: 'success'});
					console.log("Pre-login success");
				}
			})
	});

	app.post('/upload/:salt', upload.single('image'), function(req, res) {
        var encoded = base64_encode(req.file.path);
        var db = client.db('Ku');
        var originalName = req.file.originalname;

        var insertJson = {
            'details' : req.file,
            'salt' : req.params.salt,
            'originalName' : req.file.originalname,
            'base64' : encoded
        };

        db.collection('test')
            .find({originalName:originalName}).count(function (err, number){
                if(number!=0){
                    res.json({result:"Already exist file!"});
                    console.log("Already exist file!");
                }
                else{
                    db.collection('test')
                        .insertOne(insertJson , function(err, resoibse){
                            res.json({result:"Image upload success!"});
                            console.log("Image upload success!");
                })
            }    
        })
    });

    app.get('/delete/:salt/:name', function(req, res) {
        var target_name = req.params.name;
        var target_salt = req.params.salt;

	console.log(target_name);
	console.log(target_salt);

        var db = client.db('Ku');

        db.collection('test')
            .find({$and: [{originalName:target_name}, {salt:target_salt}]}).count(function(err,number){
                if(number == 0){
                    res.json({result:"No target image!"});
                    console.log("No target image!");
                }
                else{
                    db.collection('test')
                        .deleteOne({$and: [{originalName:target_name}, {salt:target_salt}]});
                    res.json({result:"Successfully removed"});
                    console.log("Successfully removed");
                }
            })
      });

    
    app.get('/download/:salt', function(req, res) {
        var target_salt = req.params.salt;
        var db = client.db('Ku');

	//db.collection('test').updateMany({}, { $unset : {_id:1}});
	db.collection('test').updateMany({}, { $unset : {details:1} });

        db.collection('test').find({salt:target_salt}).toArray(function(e, d){
        	console.log("Downloading..");
		res.json(d);
        });
      })


    app.post('/contact_update_num', function(request, response) {
	var post_data = request.body;
	var salt = post_data.salt;
	var contact_number = post_data.contact_number;

	var db = client.db('Ku');

	db.collection('user').updateOne(
		{ salt: salt },
		{ $set: { contact_number: contact_number }});
	response.json({update_success : 'success'});
	console.log('update of contact number success');
    });


    app.post('/contact_upload', (request, response, next)=> {
                var post_data = request.body;

                var salt = post_data.salt;
                var id = post_data.id;

                var db = client.db('Ku');

                var name = post_data.name;
                var mobile_number = post_data.mobile_number;
                var group = post_data.group;

                var insertJson = {
                        salt : salt,
                        id : id,
                        name : name,
                        mobile_number : mobile_number,
                        group : group
                };

                // Check exists email
                db.collection('contacts')
                        .find({$and: [{salt:salt}, {id:id}]}).count(function(err, number) {
                                if (number == 0) {
                                    db.collection('contacts')
                                        .insertOne(insertJson, function(error, res) {
                                            response.json({upload_success : 'success'});
                                        })
                                }
                                else {
                                    db.collection('contacts')
                                        .deleteOne({$and: [{salt:salt}, {id:id}]});
                                    db.collection('contacts')
                                        .insertOne(insertJson, function(error, res) {
                                            response.json({upload_success : 'success'});
                                        })
                                }
                        })
                });

    app.get('/contact_download/:salt', function(request, response) {
        var target_salt = request.params.salt;
        var db = client.db('Ku');

        db.collection('contacts').find({salt:target_salt}).toArray(function(err, result){
            if (err) throw err;
	    response.json(result);
	    //console.log(result);
        });
      })

    app.get('/contact_get_num/:salt', function (request, response) {
	var salt = request.params.salt;
	var db = client.db('Ku');
	db.collection('user').find({salt:salt}).count(function(err, number) {
	    if (number == 0) {
		response.json({get_number_success:'fail'});
		console.log('failed to get contact number');
	    }
	    else {
		db.collection('user').findOne({salt:salt}, function(error, user) {
		    var contact_number = user.contact_number;
		    response.json({get_number_success : 'success',
				   contact_number : contact_number});
		    console.log('Contact number is returned');
		});
	    }
	});
    });

    app.get('/user_name/:salt', function (request, response) {
	var salt = request.params.salt;
	var db = client.db('Ku');
	db.collection('user').find({salt:salt}).count(function(err, number) {
            if (number == 0) {
                response.json({get_name:'fail'});
                console.log('failed to get user name');
            }
            else {
                db.collection('user').findOne({salt:salt}, function(error, user) {
                    var name = user.name;
                    response.json({get_name : 'success',
                                   name : name});
                    console.log('User name has successfully been returned');
                });
            }
        });
    });

        //Start Web Server
		app.listen (80, () => {
            console.log ('Connected to MongoDB Server, WebService running on port 6880');
        })
    }
});  
