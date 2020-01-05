// Import package
var mongodb = require('mongodb');
var ObjectID = mongodb.ObjectID;
var crypto = require('crypto');
var express = require('express');
var bodyParser = require('body-parser');

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
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));


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

        //Start Web Server
		app.listen (80, () => {
            console.log ('Connected to MongoDB Server, WebService running on port 6880');
        })
    }
});  
