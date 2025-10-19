//----------đăng kí thư viện----------------
const {ObjectId} = require("@fastify/mongodb");
// Yêu cầu khung và khởi tạo nó
const fastifyServer = require('fastify')({ logger: true })
const path= require('node:path'); //Công dụng: Xử lý đường dẫn file
const crypto= require('crypto');
const { createHmac } = require("node:crypto");
// Công dụng: Mã hóa và băm dữ liệu

// Ứng dụng:

// Hash passwords
// Tạo digital signatures
// Mã hóa sensitive data
const auth = require("./auth");
const { access } = require("node:fs");
const fs = require('node:fs');
const { pipeline } = require('node:stream/promises');
const authority = require("./authority");
// Mục đích: Xử lý authorization (phân quyền)

// Có thể chứa:

// Role-based access control

// Permission checking

// Middleware phân quyền theo user role
//=========REGISTER PLUGIN=Đăng kí cái Plugin để sửa dụng===========

fastifyServer.register(require("@fastify/mongodb"), {
    forceClose: true,
    url: "mongodb://localhost:27017/banhang"
});
// Mục đích: Kết nối Fastify với MongoDB database

// Công dụng:

// Tạo kết nối đến MongoDB database tên "banhang"

// forceClose: true - đóng kết nối mạnh mẽ khi server dừng

// Cung cấp client MongoDB thông qua fastify.mongo.client

// Truy cập database: fastify.mongo.db
fastifyServer.register(require("@fastify/formbody"));
// Mục đích: Xử lý dữ liệu form (application/x-www-form-urlencoded)

// Công dụng:

// Parse dữ liệu từ HTML forms

// Làm việc với dữ liệu POST từ forms
fastifyServer.register(require("@fastify/view"), {
    engine: {
      pug: require("pug"),
    },
    root: "views",
    propertyName: "render",
});
// Mục đích: Render template views

// Công dụng:

// Sử dụng Pug template engine

// Thư mục template: "./views"

// Truy cập qua reply.render() ho fastify.render()
fastifyServer.register(require("@fastify/static"),{
    root: path.join(__dirname, "public"),
    prefix: "/public/",
});
// Mục đích: Phục vụ file tĩnh

// Công dụng:

// Phục vụ file từ thư mục "./public"

// URL truy cập: "/public/..."

// Cho phép truy cập CSS, JS, images, fonts...
fastifyServer.register(require("@fastify/jwt"), {
  secret:"Sun",
});
// Mục đích: Xử lý JSON Web Tokens (JWT)

// Công dụng:

// Tạo và xác thực JWT tokens

// Secret key: "Sun"

// Dùng cho authentication
fastifyServer.register(require("@fastify/cookie"), {
  secret:"Sun",
  hook:"onRequest",
});
// Mục đích: Xử lý cookies

// Công dụng:

// Parse và set cookies

// Signed cookies với secret "Sun"

// Hook "onRequest" - xử lý cookie sớm trong request cycle
fastifyServer.register(require('@fastify/multipart'), {attachFieldsToBody: true});
// Mục đích: Xử lý file upload và multipart forms

// Công dụng:

// Nhận file upload và form data

// attachFieldsToBody: true - tự động attach fields vào request.body

// Hỗ trợ multipart/form-data

//=================================DELARE A ROUTE===========================================================================

fastifyServer.get("/",async function(req,rep) {
  const products=await this.mongo.db.collection("products").find().toArray();
  rep.render("home",{products});
  return rep;
})
fastifyServer.get("/users",{onRequest: [auth,authority("admin")]},async function(req,rep) {
  const users =await this.mongo.db.collection("users").find().toArray();
  rep.render("user", { users })
  return rep;
})
fastifyServer.get("/create-user", function (req,rep) { 
  let username = null;
  let notification = null;
  let url = req.query.url;
  let notificationPass = null;
  switch(req.query.err){
    case"WrongAccouttype":
      notification="Tài khoản phải là email hoặc sdt !"
      username=req.query.username;
      rep.render("create-user" ,{notification,username});
      break;
    case"WrongPasstype":
      notificationPass="Mật khẩu phải có đủ 8 kí tự trở lên !"
      username=req.query.username;
      rep.render("create-user" , {notificationPass,username});
      break;
  }
  rep.render("create-user",{username,notification,notificationPass,url});
});
//router (post"/user") body url-encoded
fastifyServer.post("/user", async function(req,rep) {
  //Validate req.body
  const { username , password } = req.body;
  const emailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
  const sdtRegex = /^\d{10}$/;
  if( !emailRegex.test(username) && !sdtRegex.test(username)) {
    rep.redirect(`/create-user?err=WrongAccouttype&username=${req.body.username}`);
    if(!password && password.length < 8) {
      rep.redirect(`/create-user?err=WrongPasstype&username=${req.body.username}`);
    }
  } else {
    //transform , extract
  const salt = crypto.randomBytes(10).toString("hex");
  const hashPass = crypto.createHmac("sha256",salt).update(req.body.password).digest("hex");
  const newUser = {
    username : req.body.username,
    fullname : req.body.fullname,
    role : req.body.role,
    hashPass : hashPass,
    salt : salt
  };
  const result = await this.mongo.db.collection("users").insertOne(newUser);
  rep.redirect("/");
  }
})
fastifyServer.get("/user/:id",async function(req,rep) {
  const result = await this.mongo.db.collection("users").deleteOne({_id: new ObjectId(req.params.id)});
  rep.redirect("/users");
})
fastifyServer.get("/update-user/:id",async function(req,rep) {
  const user = await this.mongo.db.collection("users").findOne({_id: new ObjectId(req.params.id)});
  rep.render("update-user", {user});
  return rep;
})
fastifyServer.post("/update-user/:id",async function(req,rep) {
  const result = await this.mongo.db.collection("users").updateOne({_id: new ObjectId(req.params.id)},
  {$set: {
    
      fullname: req.body.fullname,
      role: req.body.role,
  }});
  rep.redirect("/users");
})

//============PRODUCT MANEGER=============

fastifyServer.get("/create-product", function (req,rep) { 
  rep.render("create-product");
})
fastifyServer.post("/product",{onRequest:[auth,authority("admin")]},async function(req, rep) {
  // const data = await req.file();
  // const filename =`${Date.now()}-${data.filename}`;

  await pipeline(req.body.image.toBuffer(), fs.createWriteStream(`public/upload/${req.body.image.filename}`));
  
  const newProduct = {
    name: req.body.name.value,
    description: req.body.description.value,
    image:`public/upload/${req.body.image.filename}`,
    price: req.body.price.value, 
  };

  req.log.info(newProduct);

  result = await this.mongo.db.collection("products").insertOne(newProduct);
  rep.redirect("/products");
});
fastifyServer.get("/products",async function(req,rep) {
  const products= await this.mongo.db.collection("products").find().toArray();
  rep.render("product",{products});
  return rep;
})
fastifyServer.get("/delete-product/:id",async function(req,rep) {
  const result = await this.mongo.db.collection("products").deleteOne({_id: new ObjectId(req.params.id)});
  rep.redirect("/products");
})
fastifyServer.get("/update-product/:id",async function(req,rep) {
  const product= await this.mongo.db.collection("products").findOne({_id: new ObjectId(req.params.id)});
  rep.render("update-product",{product});
  return rep;
})
fastifyServer.post("/update-product/:id",async function(req,rep) {
  const result= await this.mongo.db.collection("products").updateOne({_id: new ObjectId(req.params.id)},
  {$set:{
    name: req.body.name,
    image: `public/upload/${req.body.image.filename}`,
    description: req.body.description,
    price: req.body.price
  }});
  rep.redirect("/products");
})
//====LOGIN=========

fastifyServer.get("/login",function(req,rep) {
  let message=null;
  let username=null;
  let url = req.query.url || null;
  switch (req.query.err){
    case"UserNotExist":
      message="Tên Đăng Nhập Không Tồn Tại !";
      username=req.query.username;
      rep.render("login", {message,username});
      break;
    case"WrongPass":
      message="Mật Khẩu Không Chính xác !"
      username=req.query.username;
      rep.render("login", {username});
      break;
    case"unAuth":
      message=`Bạn phải đăng nhập để truy nhập tới  ${req.query.url}`;
      url=req.query.url;
      break;
    case"unAuthority":
      message = `Bạn Phải Đăng nhập với vai trò là ${req.query.role} để truy nhập ${req.query.url}`;
      url= req.query.url;
    default:
      break;
  }rep.render("login", {message,username,url});
})
fastifyServer.post("/login",async function(req,rep) {
  //validate
  const user = await this.mongo.db.collection("users").findOne({username: req.body.username});
  if(user) {
    // băm cái pass world mới nhập
    const newHpass = createHmac("sha256",user.salt).update(req.body.password).digest("hex");
    // so sánh nếu đúng thì
    if(newHpass === user.hashPass) {
      //session(back end) --- token (brower)
      //create token
      const token = this.jwt.sign({username: user.username,role: user.role});
      //Save token to brower(cokkies)
      rep.cookie("token", token);
      if(req.query.url) rep.redirect(req.query.url)
      else rep.redirect("/");
    } else {
      rep.redirect(`/login?err=WrongPass&username=${req.body.username}`);
    }
  } else {
    rep.redirect(`/login?err=UserNotExist&username=${req.body.username}`);
  }
})

//=================SHOPPING BUY=================

//const products = [
  //{id:1,name: 'Áo sơ mi',description:'Áo Sơ Mi Cổ Bẻ Tay Dài Sợi Modal Thấm Hút Trơn Dáng Vừa Giá Tốt Non Branded 19 Vol 24',price:'299',image:'/public/image/aosomi1.jpg'},
  //{id:2,name: 'Áo sơ mi',description:'Áo Sơ Mi Doraemon Và Bảo Bối Generic 15 Vol 24',price:'399',image:'/public/image/aosomi2.jpg'},
  //{id:3,name: 'Áo sơ mi',description:'Áo Sơ Mi Cổ Bẻ Tay Ngắn Sợi Nhân Tạo Thấm Hút Biểu Tượng Dáng Rộng Đơn Giản Seventy Seven 22 Vol 24',price:'316',image:'/public/image/aosomi3.jpg'},
  //{id:4,name: 'Áo sơ mi',description:'Áo Sơ Mi Cổ Bẻ Tay Dài Sợi Modal Thấm Hút Trơn Dáng Vừa Giá Tốt Non Branded 19 Vol 24',price:'499',image:'/public/image/aosomi4.jpg'},
//]
fastifyServer.get("/manager",{onRequest: [auth,authority("admin")]},function(req,rep) {
  rep.render("manager");
})
fastifyServer.get("/product-detail/:id",async function(req,rep) {
  //const productId = parseInt(req.params.id);
  //const product = products.find(p => p.id === productId);
  const product= await this.mongo.db.collection("products").findOne({_id: new ObjectId(req.params.id)});
  rep.render("product-detail",{product});
  return rep;
})
fastifyServer.post("/shopping/:id",async function(req,rep) {
  const product =await this.mongo.db.collection("products").findOne({_id: new ObjectId(req.params.id)});
  const productIndex={
    name: req.body.name,
    image: req.body.image,
    description: req.body.description,
    price: req.body.price,
  };
  const result= await this.mongo.db.collection("carts").insertOne(productIndex);
})

// Run the server!
fastifyServer.listen({ port: 3000 }, (err) => {
  if (err) {
    fastifyServer.log.error(err)
    process.exit(1)
  }
})