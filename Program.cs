
using Octokit.GraphQL;
using Octokit.GraphQL.Internal;
using Octokit.GraphQL.Model;
using Microsoft.ComponentDataService.Contracts;

var AFTER_KEY = "after";
var phv = new ProductHeaderValue("TestClient");
HttpClient httpClient = new HttpClient();
var connection = new Connection(phv, new InMemoryCredentialStore("<yourPatHere>"), httpClient);
string[] SupportedComponentTypes = new[] { "RUBYGEMS", "MAVEN", "NPM", "PIP", "NUGET", "GO", "RUST" };

foreach (var cType in SupportedComponentTypes)
{
    var results = (await DoTheQuery(cType)).ToList();
    Console.WriteLine($"Did the query for {cType}");
}

async Task<IEnumerable<GithubAdvisoryVulnerability>> DoTheQuery(string componentType)
{
    var query = new Query()
            .SecurityAdvisories(
                first: 25,
                after: new Variable(AFTER_KEY),
                last: null,
                before: null,
                classifications: null,
                identifier: new SecurityAdvisoryIdentifierFilter { Type = SecurityAdvisoryIdentifierType.Ghsa, Value = "GHSA-vm69-474v-7q2w" },
                orderBy: new SecurityAdvisoryOrder { Direction = OrderDirection.Asc, Field = SecurityAdvisoryOrderField.UpdatedAt },
                publishedSince: null,
                updatedSince: DateTimeOffset.MinValue)
            .Select(thing => new
            {
                thing.PageInfo.EndCursor,
                thing.PageInfo.HasNextPage,
                thing.TotalCount,
                Items = thing.Nodes.Select(advisory => new
                {
                    Vulnerabilities = advisory
                        .Vulnerabilities(
                            100, // first
                            null, // after
                            null, // last
                            null, // before
                            null, // classifications
                            (SecurityAdvisoryEcosystem)Enum.Parse(typeof(SecurityAdvisoryEcosystem), componentType, true), // ecosystem
                            null, // orderBy
                            null, // package
                            null) // severities
                        .Nodes.Select(vuln =>
                        new
                        {
                            // keep queried properties in sync with QueryVulnerabilitiesForComponent
                            advisory.Description,
                            advisory.PublishedAt,
                            FirstPatchedVersion = vuln.FirstPatchedVersion != null ? vuln.FirstPatchedVersion.Identifier : null,
                            Identifiers = vuln.Advisory != null && vuln.Advisory.Identifiers != null ? vuln.Advisory.Identifiers.Select(x => new { x.Type, x.Value }).ToList() : null,
                            References = vuln.Advisory != null && vuln.Advisory.References != null ? vuln.Advisory.References.Select(x => new { x.Url }).ToList() : null,
                            Summary = vuln.Advisory != null ? vuln.Advisory.Summary : null,
                            AdvisoryId = vuln.Advisory != null ? vuln.Advisory.Id : default,
                            PackageName = vuln.Package.Name,
                            advisory.UpdatedAt,
                            vuln.Package.Ecosystem,
                            vuln.Severity,
                            vuln.VulnerableVersionRange,
                            advisory.WithdrawnAt
                        }).ToList()
                }).ToList()
            })
             .Compile();


    IEnumerable<GithubAdvisoryVulnerability> result = await RunQueryAllPagesAsync(query);
    return result;
}

async Task<IEnumerable<GithubAdvisoryVulnerability>> RunQueryAllPagesAsync<T>(ICompiledQuery<T> compiledQuery)
{
    var vars = new Dictionary<string, object>
            {
                { AFTER_KEY, null },
            };

    dynamic result = await connection.Run(compiledQuery, vars);
    IEnumerable<dynamic> l1 = result.Items;
    IEnumerable<dynamic> dynamicVulns = l1.SelectMany(advisory =>
    {
        IEnumerable<dynamic> vulns = advisory.Vulnerabilities;
        return vulns;
    });

    IEnumerable<GithubAdvisoryVulnerability> itemList = ConvertToGAVulnerabilities(dynamicVulns);
    List<GithubAdvisoryVulnerability> nodesFound = itemList.ToList();

    // If there are more pages, set `after` to the end cursor.
    vars[AFTER_KEY] = result.HasNextPage ? result.EndCursor : null;

    while (vars[AFTER_KEY] != null)
    {
        result = await connection.Run(compiledQuery, vars);
        vars[AFTER_KEY] = result.HasNextPage ? result.EndCursor : null;
        l1 = result.Items;
        dynamicVulns = l1.SelectMany(advisory =>
        {
            IEnumerable<dynamic> vulns = advisory.Vulnerabilities;
            return vulns;
        });
        nodesFound.AddRange(ConvertToGAVulnerabilities(dynamicVulns));
    }

    return nodesFound;
}

IEnumerable<GithubAdvisoryVulnerability> ConvertToGAVulnerabilities(IEnumerable<dynamic> vulnerabilities)
{
    return vulnerabilities.Where(x => x.Identifiers != null).Select(vuln =>
    {
        IEnumerable<dynamic> identifiers = vuln.Identifiers;
        IEnumerable<dynamic> references = vuln.References ?? Enumerable.Empty<dynamic>();

        var result = new GithubAdvisoryVulnerability
        {
            Description = vuln.Description,
            UpdatedAt = vuln.UpdatedAt,
            PublishedAt = vuln.PublishedAt,
            FirstPatchedVersion = vuln.FirstPatchedVersion,
            Identifiers = identifiers.Select(x => new GithubAdvisoryIdentifier { Type = x.Type, Value = x.Value }).ToList(),
            References = references.Select(x => new GithubAdvisoryReference { Url = x.Url }).ToList(),
            Summary = vuln.Summary,
            AdvisoryId = vuln.AdvisoryId.Value,
            PackageName = vuln.PackageName,
            Ecosystem = Enum.GetName(typeof(SecurityAdvisoryEcosystem), vuln.Ecosystem),
            Severity = Enum.GetName(typeof(SecurityAdvisorySeverity), vuln.Severity),
            VulnerableVersionRange = vuln.VulnerableVersionRange,
            WithdrawnAt = vuln.WithdrawnAt
        };

        Console.WriteLine($"{result.AdvisoryId} {result.PublishedAt}");

        return result;
    }).ToList();
}