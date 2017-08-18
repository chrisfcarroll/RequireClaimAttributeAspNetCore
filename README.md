# RequireClaimAttributeAspNetCore

AspNet Core has simpled Attribute-based, declarative authorization for Roles and Policies but not for Claims. This project adds authorization for Claims using the "expected" Attribute-based syntax. The attribute inherits from AuthorizeAttribute and can be applied to Controller or to Action.

        [RequireClaim("AClaimType",Value = "RequiredValue")]
        public IActionResult Action(){}

        [RequireClaim("AClaimType")]
        public IActionResult Action(){}

#Usage
In Startup.cs:

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            services.AddRequireClaimAttributeAuthorization();
        }
