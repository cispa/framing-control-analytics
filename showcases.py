from libanalyzer import *

FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0"
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
         "Chrome/77.0.3865.75 Safari/537.36"
IE = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
OPERA_MINI = "Opera/9.80 (Android; Opera Mini/12.0.1987/37.7327; U; pl) Presto/2.12.423 Version/12.16"
EDGE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
       "Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763"

NO_HEADER = "WARN_NO_HEADER"


def analyze(site: str, data: dict) -> None:
    """
    Main analytics functionality

    :param site: The Origin of the deploying site
    :param data: Collected data (user-agent & policies)
    :return: Nothing, it only prints results
    """
    inc = find_inconsistencies(data, site)
    print('~~ Investigating:', site)
    if is_inconsistent(inc):
        if is_sec_oriented(inc):
            print('Status: SecurityOriented', inc)
        elif is_comp_oriented(inc):
            print('Status: CompatibilityOriented:', inc)
        else:
            print('Status: Inconstancy:', inc)
    else:
        print('Status: Consistent')


def main():
    site = 'https://example.com'
    data = {
        FIREFOX: {
            "xfo": "SAMEORIGIN",
            "csp": "'self'"
        },
        CHROME: {
            "xfo": "https://google.com",
            "csp": "*"
        },
    }
    analyze(site, data)


if __name__ == '__main__':
    main()
