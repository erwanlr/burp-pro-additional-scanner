package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.*;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    private static Pattern ASP_VERSION_PATTERN = Pattern.compile("X-AspNet-Version: ([0-9].[^,]+),");
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        helpers        = callbacks.getHelpers();
        
        callbacks.setExtensionName("ASP.NET Version Detector");
        //callbacks.issueAlert("Loaded");
        
        callbacks.registerScannerCheck(this);
    }

    //
    // implement IScannerCheck
    //
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        String headers  = helpers.analyzeResponse(baseRequestResponse.getResponse()).getHeaders().toString();
        Matcher matcher = ASP_VERSION_PATTERN.matcher(headers);
        
        if (matcher.find())
        {
            String version = matcher.group(1);
            List<int[]> versionPosition = new ArrayList<int[]>();
            versionPosition.add(new int[] { matcher.start()-1, matcher.end()-2 });

            List<IScanIssue> issues = new ArrayList(1);

            issues.add(new CustomScanIssue(
                baseRequestResponse.getHttpService(),
                helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, versionPosition) }, 
                "ASP.NET Version - " + version,
                "The X-AspNet-Version response header value has been detected",
                "Low")
            );
            return issues;
        }
        else return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
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
