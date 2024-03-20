using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.ComponentDataService.Contracts
{
    public class GithubAdvisoryIdentifier
    {
        public string Type { get; set; }
        public string Value { get; set; }
    }

    public class GithubAdvisoryReference
    {
        public string Url { get; set; }
    }

    public class GithubAdvisoryVulnerability
    {
        public string FirstPatchedVersion { get; set; }
        public IEnumerable<GithubAdvisoryIdentifier> Identifiers { get; set; }
        public IEnumerable<GithubAdvisoryReference> References { get; set; }
        public string Summary { get; set; }
        public string AdvisoryId { get; set; }
        public string PackageName { get; set; }
        public string Ecosystem { get; set; }
        public string Severity { get; set; }
        public string VulnerableVersionRange { get; set; }
        public DateTimeOffset UpdatedAt { get; set; }
        public string Description { get; set; }
        public DateTimeOffset? WithdrawnAt { get; set; }
        public DateTimeOffset PublishedAt { get; set; }

        public string GetPrimaryIdentifier()
        {
            // AdvisoryID is not stable, better look at GHSA. For more info see:
            //     #1 A "feature" by GH: https://github.blog/2021-02-10-new-global-id-format-coming-to-graphql/
            //     #2 A bug https://github.com/github/github/pull/171856 that affected the hashed ID.
            return Identifiers?.First(i => i.Type.Equals("GHSA", StringComparison.OrdinalIgnoreCase)).Value;
        }
    }
}
