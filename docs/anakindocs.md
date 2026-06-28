POST Search
Perform an AI-powered web search

POST
https://api.anakin.io/v1/search

Perform an AI-powered web search. Returns an AI-generated summary alongside structured search results with citations, snippets, and relevance scores. Results are returned synchronously.

Request Body
{
  "prompt": "latest AI developments 2024",
  "limit": 5
}
Copy
Parameter	Type	Description
prompt required	string	Search query or question
limit	number	Maximum number of results to return. Default 5.
Response
200 OK
{
  "id": "63385e99-3ef5-4667-84a7-e7b398ec8e06",
  "results": [
    {
      "url": "https://example.com/article",
      "title": "AI Developments 2024",
      "snippet": "Recent advancements in AI...",
      "date": "2024-01-15",
      "last_updated": "2024-01-20"
    }
  ]
}
Copy
Response Fields
Field	Type	Description
id	string	Unique identifier for the search request
results	array	Array of search result objects
results[].url	string	Source URL
results[].title	string	Page title
results[].snippet	string	Relevant text excerpt
results[].date	string	Publication date (when available)
results[].last_updated	string	Last updated date (when available)
Code Examples
cURL
Python
JavaScript
import requests

response = requests.post(
    'https://api.anakin.io/v1/search',
    headers={'X-API-Key': 'your_api_key'},
    json={
        'prompt': 'latest AI developments 2024',
        'limit': 5
    }
)

data = response.json()
print(f"Search ID: {data['id']}")

for result in data['results']:
    print(f"\nTitle: {result['title']}")
    print(f"URL: {result['url']}")
    print(f"Snippet: {result['snippet']}")