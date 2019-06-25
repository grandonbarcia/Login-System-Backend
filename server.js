var express =  require('express');
var jwt    =   require('jsonwebtoken');
var cors   =   require('cors');
var monk   =   require('monk');
var bcrypt =   require('bcryptjs');
var Joi    =   require('@hapi/joi'); //@hapi/joi

var app = express();
app.use(cors());
app.use(express.json());
app.listen(process.env.PORT || 8080 , () => {
  console.log("connection successfull");
});

var db = monk('mongodb://brandon123:brandon123@cluster0-shard-00-00-n5x5g.mongodb.net:27017,cluster0-shard-00-01-n5x5g.mongodb.net:27017,cluster0-shard-00-02-n5x5g.mongodb.net:27017/login-system?ssl=true&replicaSet=Cluster0-shard-0&authSource=admin&retryWrites=true');
var users = db.get('users');


/* GET home page. */
app.get('/', function(req, res, next) {
  users
    .find()
    .then(users => {
      res.json(users);
    });
});

app.post('/admin', verifyToken, (req, res) => {

  jwt.verify(req.token, 'secretkey', (err, authData) => {
    if(err) {
      res.sendStatus(403);
    } else {

      users
        .find()
        .then(users => {
          res.json(users);
        });
    }
  });


});

app.post('/login', function(req, res, next) {

    const body = {
      email: req.body.email.toString(),
      password: req.body.password.toString()
    };

    users
      .find({"email" : body.email})
      .then( users => {
        let isValidated;

        isValidated = bcrypt.compareSync(body.password, users[0].password);

        console.log(isValidated);


        if (isValidated){
          console.log("right password");
          jwt.sign({users}, 'secretkey', {expiresIn: '30s'},  (err, token) => {
              res.json({
                token
              });//res.json
          });//jwt
        } else {
          console.log("is not validated");
        }//else
      });//then
});//login


app.post('/', function(req, res, next) {
  if(req.body) {
    //insert into db...
    const body = {
      name: req.body.name.toString(),
      email: req.body.email.toString(),
      username: req.body.username.toString(),
      password: req.body.password.toString(),
      date: new Date()
    };


    const schema = Joi.object().keys({
          name:     Joi.string().min(4).max(30).required(),
          email:    Joi.string().trim().email().required(),
          username: Joi.string().alphanum().min(3).max(30).required(),
          password: Joi.string().min(5).max(10).required()

    });



    const result = Joi.validate(req.body, schema);
      console.log(result);

      if ( result.error === null ) {
        bcrypt.genSalt(10, function(err, salt) {
          bcrypt.hash(body.password, salt, function(err, hash) {
            body.password = hash;
            console.log(body);
            users
              .insert(body)
              .then(createdBody => {
                res.json({
                  isValidated: true,
                  message: "this is working"
              });
            });
        });
      });
    } else {
      res.json({
        isValidated: false,
        error_field: result.error.details[0].context.key,
        message: result.error.details[0].message
      });
    }




    /*bcrypt.genSalt(10, function(err, salt) {
      bcrypt.hash(body.password, salt, function(err, hash) {
        body.password = hash;
        users
          .insert(body)
          .then(createdBody => {
            res.json(createdBody);
          });
      });
    });*/
  }
  else {
    res.status(422);
    res.json({
      message: "Hey! Name and Content are required!"
    });
  }

});

//Format of token
//Authorization: Bearer <access_token>

//Verify Token
function verifyToken(req, res, next) {
  //get Auth header value
  const bearerHeader = req.headers['authorization'];
  //Check if bearer is undefined
  if (typeof bearerHeader !== 'undefined')
  {
    //Split at the space
    const bearer = bearerHeader.split(' ');
    //Get Token From Array
    const bearerToken = bearer[1];
    //Set token
    req.token = bearerToken;
    next();


  } else {
    //Forbidden
    res.sendStatus(403);
  }
}

module.exports = app;

app.use(express.static('public'));
