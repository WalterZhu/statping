module.exports = {
    filenameHashing: true,
    outputDir: '../source/dist/',
    devServer: {
        proxy: {
            '/api' : {
                target: 'http://127.0.0.1:8080',
                changeOrigin: true,
            },
        }
    }
};
