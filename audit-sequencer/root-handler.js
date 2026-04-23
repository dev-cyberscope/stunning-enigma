// Add this AFTER requiring express
// This is a middleware to handle root path RPC requests
module.exports = function(app, rpcHandler) {
    app.post(/, rpcHandler);
};
