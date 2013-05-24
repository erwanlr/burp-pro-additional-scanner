package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Iterator;
import java.util.regex.*;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    private static Pattern ASP_VERSION_PATTERN = Pattern.compile("x-aspnet-version: ([0-9].[^,]+),", Pattern.CASE_INSENSITIVE);
    private static final int MIN_PARAMETER_VALUE_LENGTH = 3;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        helpers        = callbacks.getHelpers();
        
        callbacks.setExtensionName("Additional Scanner");
        //callbacks.issueAlert("Loaded");
        
        callbacks.registerScannerCheck(this);
    }

    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    // This method comes from http://blog.portswigger.net/2012/12/sample-burp-suite-extension-custom_20.html
    private List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length)
        {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }
        
        return matches;
    }

    //
    // implement IScannerCheck
    //
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse requestResponse)
    {
        List<IScanIssue> results = new ArrayList<IScanIssue>();

        results.addAll(doPassiveHeadersScan(requestResponse));
        results.addAll(doPassiveParametersScan(requestResponse));

        return results;
    }

    private List<IScanIssue> doPassiveHeadersScan(IHttpRequestResponse requestResponse)
    {
        List<IScanIssue> issues = new ArrayList<IScanIssue>();
        String headers = helpers.analyzeResponse(requestResponse.getResponse()).getHeaders().toString();

        IScanIssue aspNetVersionIssue = doPassiveHeadersASPNETVersionScan(headers, requestResponse);

        if (aspNetVersionIssue != null)
            issues.add(aspNetVersionIssue);

        return issues;
    }

    private IScanIssue doPassiveHeadersASPNETVersionScan(String headers, IHttpRequestResponse requestResponse)
    {
        Matcher matcher  = ASP_VERSION_PATTERN.matcher(headers);

        if (matcher.find())
        {
            String version              = matcher.group(1);
            List<int[]> versionPosition = new ArrayList<int[]>();

            versionPosition.add(new int[] { matcher.start()-1, matcher.end()-2 });

            return new ASPNETVersionIssue(
                requestResponse.getHttpService(),
                helpers.analyzeRequest(requestResponse).getUrl(), 
                new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, versionPosition) }, 
                version
            );
        }
        return null;
    }
    
    /*
      TODO:
        - scan for url param like redirect, returnurl etc (Unvalidated Redirects and Forwards)
    */
    private List<IScanIssue> doPassiveParametersScan(IHttpRequestResponse requestResponse)
    {
        IParameter parameter;
        byte[] response               = requestResponse.getResponse();
        List<IScanIssue> issues       = new ArrayList<IScanIssue>();
        List<IParameter> parameters   = helpers.analyzeRequest(requestResponse).getParameters();
        Iterator<IParameter> iterator = parameters.iterator();

        while (iterator.hasNext())
        {
            parameter = iterator.next();

            if (parameter.getType() == IParameter.PARAM_URL)
            {
                if (parameter.getValue().length() >= MIN_PARAMETER_VALUE_LENGTH)
                {
                    List<int[]> matches = getMatches(response, parameter.getValue().getBytes());

                    if (matches.size() > 0)
                    {
                        issues.add(new PotentialXSSIssue(
                            requestResponse.getHttpService(),
                            helpers.analyzeRequest(requestResponse).getUrl(), 
                            new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, null, matches) }, 
                            parameter
                        ));
                    }
                }
            }
        }

        return issues;
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
