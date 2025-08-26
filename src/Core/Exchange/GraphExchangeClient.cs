namespace Microsoft.ExtractorSuite.Core.Exchange
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core.Authentication;
    using Microsoft.Graph;
    using Microsoft.Graph.Models;


    /// <summary>
    /// Alternative Exchange client using Microsoft Graph API
    /// Provides fallback functionality when Exchange Admin API is not available
    /// </summary>
    public class GraphExchangeClient
    {

        private readonly AuthenticationManager _authManager;


u

        public GraphExchangeClient(AuthenticationManager authManager)
        {

            _authManager = authManager;

        }

        /// <summary>
        /// Search messages using Graph API (alternative to Exchange message trace)
        /// </summary>
        public async Task<IEnumerable<Message>> SearchMessagesAsync(
            string userPrincipalName,
            DateTime? startDate = null,
            DateTime? endDate = null,
            string? subject = null,
            string? from = null,
            CancellationToken cancellationToken = default)
        {

            var graphClient = _authManager.GraphClient
                ?? throw new InvalidOperationException("Graph client not initialized");


            var filter = new List<string>();

            if (startDate.HasValue)
                filter.Add($"receivedDateTime ge {startDate.Value:yyyy-MM-ddTHH:mm:ssZ}");

            if (endDate.HasValue)
                filter.Add($"receivedDateTime le {endDate.Value:yyyy-MM-ddTHH:mm:ssZ}");

            if (!string.IsNullOrEmpty(subject))
                filter.Add($"contains(subject, '{subject}')");

            if (!string.IsNullOrEmpty(from))
                filter.Add($"from/emailAddress/address eq '{from}'");

            var filterString = filter.Any() ? string.Join(" and ", filter) : null;

            var messages = await graphClient.Users[userPrincipalName]
                .Messages
                .GetAsync(config =>
                {
                    if (!string.IsNullOrEmpty(filterString))
                        config.QueryParameters.Filter = filterString;
                    config.QueryParameters.Top = 999;
                    config.QueryParameters.Select = new[] { "id", "subject", "from", "toRecipients", "receivedDateTime", "hasAttachments" };
                }, cancellationToken);

            return messages?.Value ?? new List<Message>();
        }

        /// <summary>
        /// Get mailbox settings using Graph API
        /// </summary>
        public async Task<MailboxSettings?> GetMailboxSettingsAsync(
            string userPrincipalName,
            CancellationToken cancellationToken = default)
        {

            var graphClient = _authManager.GraphClient
                ?? throw new InvalidOperationException("Graph client not initialized");


            var user = await graphClient.Users[userPrincipalName]
                .GetAsync(config =>
                {
                    config.QueryParameters.Select = new[] { "mailboxSettings" };
                }, cancellationToken);

            return user?.MailboxSettings;
        }

        /// <summary>
        /// Get mail folders for a user
        /// </summary>
        public async Task<IEnumerable<MailFolder>> GetMailFoldersAsync(
            string userPrincipalName,
            CancellationToken cancellationToken = default)
        {

            var graphClient = _authManager.GraphClient
                ?? throw new InvalidOperationException("Graph client not initialized");


            var folders = await graphClient.Users[userPrincipalName]
                .MailFolders
                .GetAsync(config =>
                {
                    config.QueryParameters.Top = 999;
                }, cancellationToken);

            return folders?.Value ?? new List<MailFolder>();
        }

        /// <summary>
        /// Get inbox rules using Graph API
        /// </summary>
        public async Task<IEnumerable<MessageRule>> GetInboxRulesAsync(
            string userPrincipalName,
            CancellationToken cancellationToken = default)
        {

            var graphClient = _authManager.GraphClient
                ?? throw new InvalidOperationException("Graph client not initialized");


            var rules = await graphClient.Users[userPrincipalName]
                .MailFolders["Inbox"]
                .MessageRules
                .GetAsync(cancellationToken: cancellationToken);

            return rules?.Value ?? new List<MessageRule>();
        }

        /// <summary>
        /// Get calendar events (useful for audit scenarios)
        /// </summary>
        public async Task<IEnumerable<Event>> GetCalendarEventsAsync(
            string userPrincipalName,
            DateTime startDate,
            DateTime endDate,
            CancellationToken cancellationToken = default)
        {

            var graphClient = _authManager.GraphClient
                ?? throw new InvalidOperationException("Graph client not initialized");


            var events = await graphClient.Users[userPrincipalName]
                .CalendarView
                .GetAsync(config =>
                {
                    config.QueryParameters.StartDateTime = startDate.ToString("yyyy-MM-ddTHH:mm:ssZ");
                    config.QueryParameters.EndDateTime = endDate.ToString("yyyy-MM-ddTHH:mm:ssZ");
                    config.QueryParameters.Top = 999;
                }, cancellationToken);

            return events?.Value ?? new List<Event>();
        }

        /// <summary>
        /// Check if user has a mailbox
        /// </summary>
        public async Task<bool> HasMailboxAsync(
            string userPrincipalName,
            CancellationToken cancellationToken = default)
        {
            try
            {

                var graphClient = _authManager.GraphClient
                    ?? throw new InvalidOperationException("Graph client not initialized");


                var user = await graphClient.Users[userPrincipalName]
                    .GetAsync(config =>
                    {
                        config.QueryParameters.Select = new[] { "mail", "proxyAddresses" };
                    }, cancellationToken);

                return !string.IsNullOrEmpty(user?.Mail);
            }
            catch
            {
                return false;
            }
        }
    }
}
