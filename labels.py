import re
import requests
from bs4 import BeautifulSoup

def fetch_title(url):
    """Fetch the title of a given URL."""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.title.string.strip() if soup.title else url
        return url
    except Exception as e:
        print(f"Error fetching title for URL {url}: {e}")
        return url

def transform_hyperlinks_in_md(file_path):
    """Transform hyperlinks in a markdown file."""
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    # Regular expression to find URLs
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')

    urls = set(re.findall(url_pattern, content))
    
    # Fetch titles and replace URLs
    for url in urls:
        title = fetch_title(url)
        content = content.replace(url, f"[{title}]({url})")

    # Save the modified content back to the file
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(content)

if __name__ == '__main__':
    file_path = input("Enter the path to your markdown file: ").strip()
    transform_hyperlinks_in_md(file_path)
    print("Hyperlinks transformed successfully.")
