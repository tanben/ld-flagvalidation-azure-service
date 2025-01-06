const Joi = require('joi') 

const VALID_ACTIONS = ['createFlag'];
const FLAG_PREFIX = 'ff_';
const TAG_REGEX = /^[a-zA-Z0-9-_]+$/;

/**
 * Joi v17.13.3
 * API: https://joi.dev/api/?v=17.13.3
 * Sandbox: https://joi.dev/tester/
 */

const accessJoiSchema = Joi.object({
  action: Joi.string()
        .valid(...VALID_ACTIONS)
        .required()
        .messages({
          'any.only': `Action must be one of: ${VALID_ACTIONS.join(', ')}`,
        }),
  resource: Joi.string()
      .required(), 
});

const tagsSchema=Joi.string()
      .pattern(TAG_REGEX)
      .min(4)
      .max(30)
      .messages({
        'string.pattern.base': 'Tags can only contain letters, numbers, hyphens and underscores',
        'string.min': 'Each tag must be at least 4 characters',
        'string.max': 'Each tag cannot exceed 30 characters'
      });

const currentVersionSchema={
  name: Joi.string()
  .required()
  .pattern(new RegExp(`^${FLAG_PREFIX}`))
  .messages({
    'string.pattern.base': `Flag name must start with ${FLAG_PREFIX} prefix`,
    'any.required': 'Name is required'
  }),

  key: Joi.string()
    .required()
    .pattern(new RegExp(`^${FLAG_PREFIX}`))
    .messages({
      'string.pattern.base': `Flag key must start with ${FLAG_PREFIX} prefix`,
      'any.required': 'Key is required'
    }),

  description: Joi.string()
    .required()
    .min(1)
    .messages({
      'string.min': 'Description must be at least 5 characters',
      'any.required': 'Description is required'
    }),

  kind: Joi.string()
    .required()
    .valid('boolean', 'multivariate', 'string', 'number')
    .messages({
      'any.only': 'Kind must be one of: boolean, multivariate, string, number',
      'any.required': 'Kind is required'
    }),

  tags: Joi.array()
  .items(tagsSchema)
    .min(1)
    .required()
    .messages({
      'array.min': 'At least one tag is required',
      'any.required': 'Tags are required'
    }),
};

module.exports = { 
    flagAction: Joi.object({
          accesses:Joi.array()
          .items(accessJoiSchema)
          .required()
          .messages({
            'any.required': 'Action is required',
        })
      }).unknown(true)
    ,flagConfig: Joi.object({
          currentVersion:Joi.object(currentVersionSchema)
          .required()
          .messages({
            'any.required': 'Flag Configuration is required',
          })
          .unknown(true)  
      })
      .required()
      .unknown(true)
    
}; 
