package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.*;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    private static Pattern ASP_VERSION_PATTERN = Pattern.compile("x-aspnet-version: ([0-9].[^,]+),", Pattern.CASE_INSENSITIVE);
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        helpers        = callbacks.getHelpers();
        
        callbacks.setExtensionName("Additional Scanner");
        //callbacks.issueAlert("Loaded");
        
        callbacks.registerScannerCheck(this);
    }

    //
    // implement IScannerCheck
    //
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse requestResponse)
    {
        return doPassiveHeadersScan(requestResponse);
    }

    private List<IScanIssue> doPassiveHeadersScan(IHttpRequestResponse requestResponse)
    {
        String  headers  = helpers.analyzeResponse(requestResponse.getResponse()).getHeaders().toString();
        Matcher matcher  = ASP_VERSION_PATTERN.matcher(headers);
        
        if (matcher.find())
        {
            String version = matcher.group(1);
            List<int[]> versionPosition = new ArrayList<int[]>();
            versionPosition.add(new int[] { matcher.start()-1, matcher.end()-2 });

            List<IScanIssue> issues = new ArrayList<IScanIssue>(1);

            issues.add(new ASPNETVersionIssue(
                requestResponse.getHttpService(),
                helpers.analyzeRequest(requestResponse).getUrl(), 
                new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, versionPosition) }, 
                version
            ));
            return issues;
        }
        else return null;
    } 

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse requestResponse, IScannerInsertionPoint insertionPoint)
    {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }
}
