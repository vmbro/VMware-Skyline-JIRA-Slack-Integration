import json
import time
import requests
from jira import JIRA
from slack_sdk.webhook import WebhookClient

APITOKEN = "Your-API-Token"
SKYLINEAPI = "https://skyline.vmware.com/public/api/data"
SKYLINEACCESS = "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize?grant_type=refresh_token"


def sendJIRA(findingDisplayName, severity, findingDescription, recommendations, findingAffectedObjects, kbLinkURLs, totalAffectedObjects, category, risk, vcenter):
    formattedKB = ""
    priority =""
    issueDescription=""
    issueKey =""
    issueRecommendation =""
    storyPoint = ""
    issueUpdated = ""
    jsonDATA = vcenter

    with open('C:/Skyline-Scripts/sites.json', 'r') as f:
        data = json.load(f)

    vcenter_list = data["sites"]
    for vcenter in vcenter_list:
        vcenter_value = vcenter["vcenter"]
        if(jsonDATA == vcenter_value):
            jiraProjectKey = vcenter["jira"]["project"]
            jiraUsername = vcenter["jira"]["username"]
            jiraToken = vcenter["jira"]["token"]
            jiraURL = vcenter["jira"]["url"]
            slackURL = vcenter["slackurl"]

    match severity:
        case "CRITICAL":
            priority = 'High'
            storyPoint = 5

        case "MODERATE":
            priority = 'Medium'
            storyPoint = 3

        case "TRIVIAL":
            priority = 'Low'
            storyPoint = 3

    for kb in kbLinkURLs:
        formattedKB = formattedKB + "* [" + kb + "|" + kb + "]\n"
    for desc in recommendations:
        issueRecommendation = issueRecommendation + desc + "\n"

    issueDescription = findingDescription + "\n\n\n" + "*Helpful Links:*\n" + formattedKB
    summary = "'" + '"' + findingDisplayName + '"' + "'"
    epicName = '"' + "Skyline Findings" + '"'
    jira_connection = JIRA(basic_auth=(jiraUsername, jiraToken), options={'server': jiraURL})
    epic = jira_connection.search_issues("project=" + jiraProjectKey + " and type='Epic'" + " and summary ~ " + epicName)
    issue_dict = {
    'project': {'key': jiraProjectKey},
    'summary': findingDisplayName,
    'description': issueDescription,
    'customfield_10000': storyPoint,
    'customfield_10001': issueRecommendation,
    'customfield_10002' : findingAffectedObjects,
    'customfield_10003' : epic[0].key,
    'labels': ["Healthcheck", "System"],
    'priority':{'name': priority},
    'issuetype': {'name': 'Task'},   
    }
    issueList = jira_connection.search_issues("project=" + jiraProjectKey + " and status='to do'" + " and summary ~ " + summary)
    
    if (issueList):
        issue = issueList[0]
        issue.update(description = issueDescription)
        issue.update(fields={'customfield_10002': findingAffectedObjects})
        issueKey = issue.key
        issueUpdated = True
    else:
        newIssue = jira_connection.create_issue(fields=issue_dict)
        issueKey = newIssue.key
        issueUpdated = False

    print("Creating issue for " + findingDisplayName)
    if issueUpdated == False:
        sendSlack(findingDisplayName, severity, totalAffectedObjects, category, risk, issueKey, jiraURL, slackURL)


def sendSlack(findingName, severity, totalAffectedObjects, category, risk, issueKey, jiraURL, slackURL):
    warningEmoji = ':warning:'
    alertEmoji1 = ':alert:'
    alertEmoji2 = ':alert-blue:'
    alertEmoji3 = ':orange_alert:'
    issueButtonURL = jiraURL + "/browse/" + issueKey
    match severity:
        case "CRITICAL":
            emoji = alertEmoji1

        case "MODERATE":
            emoji = alertEmoji2

        case "TRIVIAL":
            emoji = alertEmoji3

    webhook = WebhookClient(slackURL)
    response = webhook.send(
        text="fallback",
        blocks=[
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "{} You have new Skyline findings! {}\n*<https://skyline.vmware.com/advisor|VMware Skyline Advisor>*".format(warningEmoji, warningEmoji)
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*Finding Name:*\n{}".format(findingName)
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Product:*\n{}".format(vcenter)
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Severity:*\n{} {}".format(severity, emoji)
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Affected Objects:* {}".format(totalAffectedObjects)
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Category:* {}".format(category)
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Risk if no action taken:* {}".format(risk)
                    }
                ]
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                                "text": "Go to Issue"
                        },
                        "style": "primary",
                        "url": issueButtonURL
                    }
                ]
            },
            {
                "type": "divider"
            }
        ]
    )
    print("Sending " + findingName +" details to Slack channel...")
    


accessHeaders = {'accept': 'application/json',
                 'Content-Type': 'application/x-www-form-urlencoded'}
accessData = {'refresh_token': APITOKEN}

accessResponse = requests.post(
    url=SKYLINEACCESS, data=accessData, headers=accessHeaders)
accessResponseJson = accessResponse.json()

accessToken = accessResponseJson['access_token']


def getAffectedObject(findingList, vcenter):
    findvcenter = vcenter
    for finding in findingList:
        findingAffectedObjects = ""
        findingDisplayName = finding['findingDisplayName']
        severity = finding['severity']
        totalAffectedObjects = finding['totalAffectedObjectsCount']
        category = finding['categoryName']
        risk = finding['findingImpact']
        findingDescription = finding['findingDescription']
        recommendations = finding['recommendations']
        kbLinkURLs = finding['kbLinkURLs']
        objectCount = 1
        for object in finding['affectedObjects']:
            findingAffectedObjects += "- " + object['objectName'] + "\n"
            objectCount += 1
    print("Collecting " + findingDisplayName + " details from Skyline")
    sendJIRA(findingDisplayName, severity, findingDescription, recommendations, findingAffectedObjects, kbLinkURLs, totalAffectedObjects, category, risk, findvcenter )



headers = {'Authorization': 'Bearer ' + accessToken,
           'Content-Type': 'application/json'}

data = {'query': """{ 
  activeFindings(limit: 200) { 
    findings { 
      findingId 
      accountId 
      products 
      findingDisplayName 
      severity 
      findingDescription 
      findingImpact 
      recommendations 
      kbLinkURLs 
      recommendationsVCF 
      kbLinkURLsVCF 
      categoryName 
      findingTypes 
      firstObserved 
      totalAffectedObjectsCount 
      } 
    totalRecords 
    timeTaken 
    } 
  }"""
        }
response = requests.post(
    url=SKYLINEAPI, data=json.dumps(data), headers=headers)
responseJson = response.json()

activeFindings = responseJson['data']['activeFindings']
findings = activeFindings['findings']

with open('C:/Skyline-Scripts/sites.json', 'r') as f:
    data = json.load(f)

site_list = data["sites"]
vcenters = []
for site in site_list:
    vcenters.append(site["vcenter"])

for finding in findings:
    for vcenter in vcenters:
     if vcenter in finding['products']:
         findingId = finding['findingId']
         products = finding['products']
         findingName = finding['findingDisplayName']
         severity = finding['severity']
         affectedObjects = finding['totalAffectedObjectsCount']
         category = finding['categoryName']
         risk = finding['findingImpact']
         for product in products:
             newData = {'query': """{ 
           activeFindings(limit: 200, filter: {
           findingId: "%s" ,
     		  product: "%s"
         }) { 
           findings { 
           findingId 
           accountId 
           products 
           findingDisplayName 
           severity 
           findingDescription 
           findingImpact 
           recommendations 
           kbLinkURLs 
           recommendationsVCF 
           kbLinkURLsVCF 
           categoryName 
           findingTypes 
           firstObserved 
           totalAffectedObjectsCount
           affectedObjects(start: 0, limit: 200)  {
           sourceName
           objectName
           objectType
           version
           buildNumber
           solutionTags {
             type
             version
           }
           firstObserved
           }      
           } 
           totalRecords 
           timeTaken 
           } 
           }""" % (findingId, vcenter)
             }
 
             responseAffected = requests.post(
                 url=SKYLINEAPI, data=json.dumps(newData), headers=headers)
             time.sleep(1)
             responseAffectedJson = responseAffected.json()
             if "data" in responseAffectedJson:
                 getAffectedObject(responseAffectedJson['data']['activeFindings']['findings'], vcenter)
             else:
                 print("Response Gelmedi", responseAffectedJson)
             break
            
            
 
