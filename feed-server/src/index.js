import express from "express";
import axios from "axios";
import https from "https";

// Create Express Server
const app = express();

// Configuration
const PORT = 8080;
const HOST = "0.0.0.0";
const API_SERVICE_URL =
	"http://" + process.env.MISP_HOST + "/attributes/restSearch";
//const API_SERVICE_URL = "https://localhost/attributes/restSearch";
const user = process.env.FEED_USER;
const password = process.env.FEED_PASSWORD;
const api = process.env.MISP_API_KEY;

// Authorization
app.use("", (req, res, next) => {
	if (req.headers.authorization) {
		if (
			req.headers.authorization ==
			"Basic " + Buffer.from(user + ":" + password).toString("base64")
		) {
			next();
		} else res.sendStatus(403);
	} else res.sendStatus(403);
});

// Proxy endpoints
app.get("/", (req, res) => {
	let params = {
		returnFormat: "csv",
		type: [],
		requested_attributes: ["value"],
		enforceWarninglist: 1,
		headerless: 1,
		excludeDecayed: 1,
	};
	if (req.query.type) {
		if (req.query.type.includes("hash")) {
			params["type"].push("md5", "sha1", "sha256");
		}
		if (req.query.type.includes("ip")) {
			params["type"].push("ip-src", "ip-dst");
		}
		if (req.query.type.includes("domain")) {
			params["type"].push("domain");
		}
	} else {
		params["type"].push(
			"md5",
			"sha1",
			"sha256",
			"ip-src",
			"ip-dst",
			"domain"
		);
	}
	const config = {
		headers: {
			Authorization: api,
			"Content-Type": "application/json",
		},
	};
	const instance = axios.create({
		httpsAgent: new https.Agent({
			rejectUnauthorized: false,
		}),
	});
	instance
		.post(API_SERVICE_URL, params, config)
		.then((result) => {
			let final = "";
			if (req.query.limit) {
				//TODO poner ultimos n IOCs
				result = result.data.split("\n");
				result = result.slice(0, req.query.limit);
				result.forEach((e) => {
					final = final + e.replace(/["]/g, "") + "\n";
				});
			} else {
				final = result.data.replace(/["]/g, "");
			}
			res.setHeader("content-type", "text/plain");
			res.send(final);
		})
		.catch((error) => res.send(error.message));
});

// Start the Proxy
app.listen(PORT, HOST, () => {
	console.log(`Starting Proxy at ${HOST}:${PORT}`);
});
