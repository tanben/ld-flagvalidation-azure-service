const { HttpResponse } = require('@azure/functions');
const crypto = require('crypto');
const axios = require('axios');


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



function getValFromFlagResourcePath(id, path){
    // path example: "proj/sandbox;sandbox:env/production:flag/projidTestflag"
    // id example: "proj" or "env" or "flag"

    const pathObj = path.split(":").reduce( (acc,curr)=>{
        let [k, v]= curr.split("/");
        v = v.includes(";") ? v.split(";")[0]:v;
        acc = {...acc, [k]:v};
        return acc;
    },{});
    return pathObj[id];
}
function errorFlagDetails(jsonBody){
    if (!jsonBody){
        return {};
    }
    
    const {currentVersion,  title, titleVerb, target} = jsonBody;
    const {_maintainer:maintainer, name, kind,key, creationDate} = currentVersion;
    const path =  target.resources[0];
    delete maintainer._links;
    
    return {
        maintainer, 
        flag:{
            name, projectKey: getValFromFlagResourcePath("proj",path) ,kind, key, title, titleVerb, creationDate
        }
    };
}
async function updateFlag({field, projectKey, flagKey, value, apiKey}) {
    
    if (!field || field !="tags"){
        const message=`Operation is not recognized for this feature flag field [${field}]`;
        return {status:501,data:message};
    }

    const url = `https://app.launchdarkly.com/api/v2/flags/${projectKey}/${flagKey}`;
    console.log(url)
    const resp = await axios({
      method: 'PATCH',
      url,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': apiKey
      },
      data: {
        patch: [
          {
            op: 'add',
            path: '/tags/0',
            value
          }
        ]
      }
    });
  
    // const data = resp.data;
    // console.log(data);
    return resp;
  }

async function deleteFlag({projectKey, flagKey, value, apiKey}) {
    const url = `https://app.launchdarkly.com/api/v2/flags/${projectKey}/${flagKey}`;
    console.log(url)
    const resp = await axios({
      method: 'DELETE',
      url,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': apiKey
      }
    });
  
    // const data = resp.data;
    // console.log(data);
    return resp;
}


module.exports = {
    validateSchema,
    verifyWebhookSignature,
    updateFlag,
    deleteFlag
};