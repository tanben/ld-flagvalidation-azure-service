const { app } = require('@azure/functions');
const schemas = require("../utils/schemas.js");

const {validateSchema, verifyWebhookSignature}=require('../utils/middleware.js');
const WEBHOOK_SECRET=  process.env.WEBHOOK_SECRET;
const X_LD_HEADER=  process.env.X_LD_HEADER;

app.http('test', {
    methods: ['GET'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        context.log(`Http function processed request for url "${request.url}"`);

        const name = request.query.get('name') || await request.text() || 'world';

        return { body: `Hello, ${name}!` };
    }
});

app.http('validate-flag', {
    methods: ['POST'],
    authLevel: 'anonymous',
    handler:handleRequest
});


async function handleRequest (request, context) {

    const {headers} = request;
    const jsonBody = await request.json();

    if (!verifyWebhookSignature({headers,secret:WEBHOOK_SECRET,  jsonBody, context}) ){
        return context.res;
    }

    if (! validateSchema({schema:schemas.flagAction, jsonBody,  context}) ){
        return context.res;
    }

    if (!validateSchema({schema:schemas.flagConfig, jsonBody, context})){
        return context.res;
    }

    return { jsonBody:  {isValid:true}};
}