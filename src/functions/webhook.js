const { app, HttpResponse } = require('@azure/functions');
const schemas = require("../utils/schemas.js");
const { faker } = require('@faker-js/faker');

const {validateSchema, verifyWebhookSignature, updateFlag}=require('../utils/middleware.js');
const WEBHOOK_SECRET=  process.env.WEBHOOK_SECRET;
const X_LD_HEADER=  process.env.X_LD_HEADER;
const API_ACCESS_TOKEN= process.env.API_ACCESS_TOKEN;


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


app.http('flags', {
    methods: ['PATCH'],
    authLevel: 'anonymous',
    handler:handleTagsRequest
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


async function handleTagsRequest (request, context) {
    const jsonBody = await request.json();
    const projectKey = request.query.get('projectKey');
    const flagKey = request.query.get('flagKey');
    const apiKey = API_ACCESS_TOKEN;

    console.log(jsonBody);
    console.log(request.query)

    const {status, data}=  await updateFlag({field:'tags', projectKey, flagKey, value:faker.food.fruit(), apiKey})
    context.res = new HttpResponse({
        status : status,
        jsonBody:data
    })
    return context.res
}
