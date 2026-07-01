const express = require("express");
const axios = require("axios");

const app = express();

app.use(express.raw({ type: "*/*", limit: "20mb" }));

const SECRET_TOKEN = process.env.SECRET_TOKEN || "anssstore2026";

app.get("/health", (req, res) => {
    res.json({
        status: "ok",
        proxy: "ivasms",
        online: true
    });
});

app.all("/proxy/*", async (req, res) => {

    if (req.headers["x-proxy-token"] !== SECRET_TOKEN) {
        return res.status(401).send("Unauthorized");
    }

    const path = req.originalUrl.replace(/^\/proxy/, "");

    const targetUrl = "https://ivasms.com" + path;

    try {

        const headers = { ...req.headers };

        delete headers.host;
        delete headers["x-proxy-token"];

        const response = await axios({
            url: targetUrl,
            method: req.method,
            headers,
            data: req.body,
            responseType: "arraybuffer",
            maxRedirects: 5,
            validateStatus: () => true
        });

        Object.entries(response.headers).forEach(([k, v]) => {
            if (v) res.setHeader(k, v);
        });

        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("X-Final-Url", response.request.res.responseUrl);

        res.status(response.status).send(response.data);

    } catch (err) {

        res.status(502).json({
            error: err.message
        });

    }

});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("Proxy running on port", PORT);
});
