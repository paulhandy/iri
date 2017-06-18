package com.iota.iri.service.dto;

/**
 * Created by paul on 2/10/17.
 */
public class IXIResponse extends AbstractResponse {
    private Object res;

    public static IXIResponse create(Object myixi) {
        IXIResponse ixiResponse = new IXIResponse();
        ixiResponse.res = myixi;
        return ixiResponse;
    }

    public Object getResponse() {
        return res;
    }
}
