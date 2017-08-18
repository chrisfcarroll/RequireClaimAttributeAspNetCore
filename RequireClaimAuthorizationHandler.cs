using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Internal;
using Microsoft.Extensions.DependencyInjection;

namespace RequireClaimAttributeAuthorization
{
    /// <summary>An AuthorizeAttribute which allows declarative specification of Claims-based requirements.</summary>
    public class RequireClaimAttribute : AuthorizeAttribute
    {
        /// <summary>The <see cref="System.Type"/> that must be satisfied. This value may not be null.</summary>
        public string Type { get; }

        /// <summary>The <see cref="Claim.Value"/> that must be satisfied. This value may be null, in which case only the <see cref="Claim.Type"/> 
        /// need match and <see cref="Claim.Value"/>is ignored.</summary>
        public string Value { get; set; }

        public RequireClaimAttribute(string type)
        {
            if (type==null) throw new ArgumentNullException(nameof(type));
            if (type.Length==0) throw new ArgumentException("Claim Type cannot be empty", nameof(type));
            Type = type;
            base.Policy = Policy;
        }

        public new string Policy { get; } = PolicyName;

        /// <summary>
        /// The Name under which the <see cref="RequireClaimAuthorizationHandler"/> is register by <see cref="AuthorizationOptions.AddPolicy(string,System.Action{Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder})"/>
        /// </summary>
        public static readonly string PolicyName = typeof(RequireClaimAttribute).AssemblyQualifiedName;
    }

    public class RequireClaimAuthorizationHandler : AuthorizationHandler<RequireClaimAuthorizationHandler>, IAuthorizationRequirement
    {
        /// <summary>
        /// Allow Authorization if the <see cref="ClaimsPrincipal"/> for the current request has the <see cref="Claim"/>(s) required by any
        /// <see cref="RequireClaimAttribute"/>s decorating the Mvc Controller or the Action being attempted.
        /// </summary>
        /// <param name="context">
        /// The authorization context. Authorization will only succeed if the <see cref="AuthorizationHandlerContext.Resource"/> is an instance of
        /// <see cref="Microsoft.AspNetCore.Mvc.Filters.AuthorizationFilterContext"/> and has a valid <see cref="ControllerActionDescriptor"/>; 
        /// </param>
        /// <param name="requirement">The requirement to evaluate: an instance of this class, <see cref="RequireClaimAuthorizationHandler"/></param>
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RequireClaimAuthorizationHandler requirement)
        {
            if (context.User != null 
                && context.Resource is Microsoft.AspNetCore.Mvc.Filters.AuthorizationFilterContext mvcContext
                && mvcContext.ActionDescriptor is ControllerActionDescriptor actionDescriptor)
            {
                var controllerClaims = actionDescriptor.ControllerTypeInfo.CustomAttributes.Where(cad => cad.AttributeType == typeof(RequireClaimAttribute));
                var actionClaims = actionDescriptor.MethodInfo.CustomAttributes.Where(cad=>cad.AttributeType==typeof(RequireClaimAttribute));
                var actualClaims = context.User.Claims;
                var ids = context.User.Identities;
                bool satisfiesControllerClaims = controllerClaims.All(c => actualClaims.Any(a=> a.Satisfies(c)));
                bool satisfiesActionClaims = actionClaims.All(c => actualClaims.Any(a => a.Satisfies(c)));
                if (satisfiesControllerClaims && satisfiesActionClaims ) context.Succeed(requirement);
            }
            return TaskCache.CompletedTask;
        }
    }

    public static class RequireClaimAuthorizationExtensions
    {
        /// <summary>
        /// Enable the use of <see cref="RequireClaimAttribute"/> to declare Claims-based Authorization in Attributes of the Controller and/or Action
        /// </summary>
        /// <param name="services"></param>
        public static void AddRequireClaimAttributeAuthorization(this IServiceCollection services)
        {
            services.AddAuthorization(o => { o.AddPolicy(RequireClaimAttribute.PolicyName, p => p.AddRequirements(new RequireClaimAuthorizationHandler()) ); });
        }

        public static bool EqualsTypeValue(this Claim left, Claim right)
        {
            return left.Type == right.Type && left.Value == right.Value;
        }

        public static bool Satisfies(this Claim left, RequireClaimAttribute right)
        {
            return left.Type == right.Type && left.Value == right.Value;
        }
        public static bool Satisfies(this Claim left, CustomAttributeData right)
        {
            if (right.AttributeType != typeof(RequireClaimAttribute)) return false;
            var type = right.ConstructorArguments.First().Value as String;
            var value= right.NamedArguments.First(a=>a.MemberName=="Value").TypedValue.Value as String;
            return left.Type == type && left.Value == value;
        }

        public static bool Contains<T>(this IEnumerable<T> collection, Func<T, bool> predicate)
        {
            return collection.Any(predicate);
        }
    }
}