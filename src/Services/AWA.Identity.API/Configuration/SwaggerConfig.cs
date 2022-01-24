namespace AWA.Identity.API.Configuration
{
    public static class SwaggerConfit
    {
        public static IServiceCollection AddSwaggerConfiguration(this IServiceCollection services)
        {
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc(name: "v1", new Microsoft.OpenApi.Models.OpenApiInfo
                {
                    Title = "AWA - Identity",
                    Description = "API responsável pela autenticação da aplicação",
                    Contact = new Microsoft.OpenApi.Models.OpenApiContact { Name = "Lucas Panetto Santos", Email = "lucaspanetto@ucl.br" }
                });
            });

            return services;
        }

        public static IApplicationBuilder UseSwaggerConfiguration(this IApplicationBuilder app)
        {
            app.UseSwagger();
            app.UseSwaggerUI();

            return app;
        }
    }
}
