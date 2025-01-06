const { HttpResponse } = require('@azure/functions');
const crypto = require('crypto');


function formatErrorMessage(error, details={}){
    
    return  {
        isValid: false,
        ...details,
        errors: error.details.map(err => ({
            field: err.path.join('.'),
            message: err.message
        }))
    };
}
function computeSignature(jsonBody, secret) {
    var signature = crypto
        .createHmac("sha256", secret)
        .update(JSON.stringify(jsonBody), "utf-8")
        .digest("hex");
    
    return signature;
}

function validateSchema({schema, jsonBody, context}){
      
    
    const { error } = schema.validate( jsonBody ,{ 
        abortEarly: false 
        });

    if (typeof error !== 'undefined'){
        const {_maintainer:maintainer} = jsonBody.currentVersion;
        delete maintainer._links;


        context.res= new HttpResponse({
            status:422,  
            jsonBody: formatErrorMessage(error,  errorFlagDetails(jsonBody))
        })
    
        return false;
    }
    return true;
}

function verifyWebhookSignature({headers, secret,  jsonBody, context}){
    const error={details:[]};
    const X_LD_HEADER=  process.env.X_LD_HEADER;
    const headerSecret = headers.get(X_LD_HEADER);

    if (!headerSecret){
        error.details=[ {path:[X_LD_HEADER], message:`Missing header:${X_LD_HEADER}`}];
    } else if ( computeSignature(jsonBody, secret) !== headerSecret) {

        error.details=[{path:[X_LD_HEADER], message:`Invalid signature`}];
    }

    if (error.details.length>0){
        context.res= new HttpResponse({
            status:401,  
            jsonBody: formatErrorMessage(error, errorFlagDetails(jsonBody))
        })
        return false;
    }
    
    return true;
}



function errorFlagDetails(jsonBody){
    if (!jsonBody){
        return {};
    }
    
    const {currentVersion,  title, titleVerb} = jsonBody;
    const {_maintainer:maintainer, name, kind,key, creationDate} = currentVersion;
    delete maintainer._links;
    
    return {
        maintainer, 
        flag:{
            name, kind, key, title, titleVerb, creationDate
        }
    };
}

module.exports = {
    validateSchema,
    verifyWebhookSignature
};