/**
 * Generated by `createschema onboarding.OnBoardingStep 'icon:Text; title:Text; description:Text; action:Select:create,read,update,delete; entity:Text; onBoarding:Relationship:OnBoarding:SET_NULL;'`
 */

async function canReadOnBoardingSteps ({ authentication: { item: user } }) {
    if (!user) return false
    if (user.isAdmin) return {}

    return {
    }
}

async function canManageOnBoardingSteps ({ authentication: { item: user }, originalInput, operation, itemId }) {
    if (!user) return false
    if (user.isAdmin) return true
    if (operation === 'create') {
        return true
    } else if (operation === 'update') {
        return true
    }

    return false
}

/*
  Rules are logical functions that used for list access, and may return a boolean (meaning
  all or no items are available) or a set of filters that limit the available items.
*/
module.exports = {
    canReadOnBoardingSteps,
    canManageOnBoardingSteps,
}