using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Web;
using Newtonsoft.Json.Linq;
using Skybrud.Umbraco.Vulnerabilities.Models;
using Umbraco.Core.Logging;
using Umbraco.Web.HealthCheck;

namespace Skybrud.Umbraco.Vulnerabilities {


    [HealthCheck("BA1BD954-5D6D-457D-A3D3-DC3F84B52C70", "Assemblies", Description = "Checks installed assemblies against a list of known vulnerabilities. By default, this only includes DLLs released by Umbraco, but can be configured to include other DLLs as well.", Group = "Security")]
    public class AssembliesHealthCheck : HealthCheck {

        public AssembliesHealthCheck(HealthCheckContext healthCheckContext) : base(healthCheckContext) {

            
            
        }

        public override IEnumerable<HealthCheckStatus> GetStatus() {

            List<HealthCheckStatus> found = new List<HealthCheckStatus>();

            string[] feeds = new [] {
                "https://gist.githubusercontent.com/abjerner/9574a063498924440ce82f1b665c4a82/raw/Umbraco.json",
                "https://gist.githubusercontent.com/abjerner/9574a063498924440ce82f1b665c4a82/raw/Skybrud.json",
                //"https://gist.githubusercontent.com/abjerner/9574a063498924440ce82f1b665c4a82/raw/SkybrudNotFound.json"
            };


            foreach (string feedUrl in feeds) {

                string contents;
                try {
                    WebClient wc = new WebClient {Encoding = Encoding.UTF8};
                    contents = wc.DownloadString(feedUrl);
                } catch (Exception ex) {
                    LogHelper.Error<AssembliesHealthCheck>("Unable to fetch feed from URL: " + feedUrl, ex);
                    found.Add(new HealthCheckStatus("Unable to fetch feed from URL <strong>" + feedUrl + "</strong>") {
                        ResultType = StatusResultType.Error,
                        Actions = Enumerable.Empty<HealthCheckAction>()
                    });
                    continue;
                }

                VulnerabilityFeed feed;
                try {
                    feed = JObject.Parse(contents).ToObject<VulnerabilityFeed>();
                } catch (Exception ex) {
                    LogHelper.Error<AssembliesHealthCheck>("Unable to parse feed from URL: " + feedUrl, ex);
                    found.Add(new HealthCheckStatus("Unable to parse feed from URL <strong>" + feedUrl + "</strong>") {
                        ResultType = StatusResultType.Error,
                        Actions = Enumerable.Empty<HealthCheckAction>()
                    });
                    continue;
                }

                try {

                    foreach (Assembly assembly in AppDomain.CurrentDomain.GetAssemblies()) {

                        foreach (VulnerabilityProduct product in feed.Products) {

                            foreach (VulnerabilityIssue issue in product.Issues) {

                                if (issue.IsAffected(assembly)) {

                                    string name = HttpUtility.HtmlEncode(assembly.FullName.Split(',')[0]);
                                    string version = HttpUtility.HtmlEncode(assembly.GetName().Version.ToString());
                                    string productName = HttpUtility.HtmlEncode(product.Name);

                                    StringBuilder sb = new StringBuilder();

                                    sb.AppendLine("Assembly <strong>" + name + "</strong> at version <strong>" + version + "</strong>");
                                    sb.AppendLine("of <strong>" + productName + "</strong> contains a known issue");
                                    sb.AppendLine("of the type <strong>" + issue.Type + "</strong>");
                                    sb.AppendLine("and with the severity <strong>" + issue.Severity + "</strong>");
                                    sb.AppendLine("and with the name <strong>" + HttpUtility.HtmlEncode(issue.Name) + "</strong>.");

                                    if (issue.HasDescription) {
                                        sb.AppendLine("<div><small>" + issue.Description + "</small></div>");
                                    }

                                    if (issue.HasUrl) {
                                        try {
                                            var uri = new Uri(issue.Url);
                                            sb.AppendLine("<div><a href=\"" + issue.Url + "\" target=\"_blank\" class=\"btn btn-success btn-small\">Read more at <u>" + uri.Host + "</u></a></div>");
                                        } catch (Exception) {
                                            sb.AppendLine("<div><a href=\"" + issue.Url + "\" target=\"_blank\" class=\"btn btn-success btn-small\">Read more</a></div>");
                                        }
                                    }

                                    found.Add(new HealthCheckStatus(sb.ToString()) {
                                        ResultType = issue.Type == "warning" || issue.Type == "patch" ? StatusResultType.Warning : StatusResultType.Error,
                                        Actions = Enumerable.Empty<HealthCheckAction>()
                                    });

                                }

                            }

                        }

                    }

                } catch (Exception ex) {

                    LogHelper.Error<AssembliesHealthCheck>("Unable to parse feed from URL: " + feedUrl, ex);

                    found.Add(new HealthCheckStatus("Unable to parse feed from URL <strong>" + feedUrl + "</strong>") {
                        ResultType = StatusResultType.Error,
                        Actions = Enumerable.Empty<HealthCheckAction>()
                    });

                }

            }

            if (found.Any()) return found;

            return new [] {
                new HealthCheckStatus("Everything appears to be in order.") {
                    ResultType = StatusResultType.Success,
                    Actions = Enumerable.Empty<HealthCheckAction>() 
                }
            };


        }

        public override HealthCheckStatus ExecuteAction(HealthCheckAction action) {
            throw new NotImplementedException();
        }

    }

}