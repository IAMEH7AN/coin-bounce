const mongoose =require('mongoose');
const {MONGODB_CONNECTION_STRING}=require('../config/index')
const dbConnect =async()=>{
try {
    const conn=await mongoose.connect(MONGODB_CONNECTION_STRING)
    console.log(`db connected at host: ${conn.connection.host}`);
} catch (error) {
    console.log(`Error in db connection: ${error}`);
}

}
module.exports=dbConnect;