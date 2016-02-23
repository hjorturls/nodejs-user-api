var config = {};
config.mongo = {};
config.facebook = {};

config.mongo.connection = "mongodb://localhost:27017/your_mongo_db";
config.facebook.client_id = "xxxxxx"
config.facebook.client_secret = "xxxxxxx"
config.facebook.me = "https://graph.facebook.com/v2.5/me?fields=name,email&access_token=";
// A better option would be to use certificates, but this will do for the purpose of the demo
config.jwtsecret = "m$qE'V/D=]bK9hq_HmhqC<hynvkRM{f7^]H6Hzn/Dax4^UH7E]wRn9p!G.+vXZ++";

module.exports = config;