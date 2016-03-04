/**
 * 
 */
package org.mobicents.jss7.standalone.example.ussd;

import org.apache.log4j.Logger;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.sctp.ManagementImpl;
import org.mobicents.protocols.ss7.m3ua.ExchangeType;
import org.mobicents.protocols.ss7.m3ua.Functionality;
import org.mobicents.protocols.ss7.m3ua.IPSPType;
import org.mobicents.protocols.ss7.m3ua.Asp;
import org.mobicents.protocols.ss7.m3ua.M3UAManagement;
import org.mobicents.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.mobicents.protocols.ss7.m3ua.parameter.RoutingContext;
import org.mobicents.protocols.ss7.m3ua.parameter.TrafficModeType;
import org.mobicents.protocols.ss7.map.MAPStackImpl;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContext;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContextName;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContextVersion;
import org.mobicents.protocols.ss7.map.api.MAPDialog;
import org.mobicents.protocols.ss7.map.api.MAPException;
import org.mobicents.protocols.ss7.map.api.MAPMessage;
import org.mobicents.protocols.ss7.map.api.MAPProvider;
import org.mobicents.protocols.ss7.map.api.dialog.MAPAbortProviderReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPAbortSource;
import org.mobicents.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic;
import org.mobicents.protocols.ss7.map.api.dialog.MAPRefuseReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPUserAbortChoice;
import org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.mobicents.protocols.ss7.map.api.primitives.AddressNature;
import org.mobicents.protocols.ss7.map.api.primitives.AddressString;
import org.mobicents.protocols.ss7.map.api.primitives.IMSI;
import org.mobicents.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.mobicents.protocols.ss7.map.api.primitives.NumberingPlan;
import org.mobicents.protocols.ss7.map.api.primitives.USSDString;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ActivateSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ActivateSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.DeactivateSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.DeactivateSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.EraseSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.EraseSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.GetPasswordRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.GetPasswordResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.InterrogateSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.InterrogateSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.MAPDialogSupplementary;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.RegisterPasswordRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.RegisterPasswordResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.RegisterSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.RegisterSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSResponse;
import org.mobicents.protocols.ss7.map.datacoding.CBSDataCodingSchemeImpl;
import org.mobicents.protocols.ss7.map.primitives.AddressStringImpl;
import org.mobicents.protocols.ss7.mtp.Mtp3UserPart;
import org.mobicents.protocols.ss7.sccp.impl.SccpStackImpl;
import org.mobicents.protocols.ss7.tcap.TCAPStackImpl;
import org.mobicents.protocols.ss7.tcap.api.TCAPStack;
import org.mobicents.protocols.ss7.tcap.asn.ApplicationContextName;
import org.mobicents.protocols.ss7.tcap.asn.comp.Problem;

/**
 * @author amit bhayani
 * 
 */
/**
 * @author erobhwa
 *
 */
public class SctpClient extends AbstractSctpBase {

	private static Logger logger = Logger.getLogger(SctpClient.class);

	// SCTP
	private ManagementImpl sctpManagement;

	// M3UA
	private M3UAManagement clientM3UAMgmt;

	// SCCP
	private SccpStackImpl sccpStack;

	// TCAP
	private TCAPStack tcapStack;

	// MAP
	private MAPStackImpl mapStack;
	private MAPProvider mapProvider;

	/**
	 * 
	 */
	public SctpClient() {
		// TODO Auto-generated constructor stub
	}

	protected void initializeStack(IpChannelType ipChannelType) throws Exception {

		this.initSCTP(ipChannelType);

		// Initialize M3UA first
		this.initM3UA();

		// Initialize SCCP
		this.initSCCP();

		// Initialize TCAP
		this.initTCAP();

		// Initialize MAP
		this.initMAP();

		// FInally start ASP
		// Set 5: Finally start ASP
		this.clientM3UAMgmt.startAsp("ASP1");
	}

	private void initSCTP(IpChannelType ipChannelType) throws Exception {
		logger.debug("Initializing SCTP Stack ....");
		this.sctpManagement = new ManagementImpl("Client");
		this.sctpManagement.setSingleThread(true);
		this.sctpManagement.start();
		this.sctpManagement.setConnectDelay(10000);
		this.sctpManagement.removeAllResourses();

		// 1. Create SCTP Association
		sctpManagement.addAssociation(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, CLIENT_ASSOCIATION_NAME,
				ipChannelType, null);
		logger.debug("Initialized SCTP Stack ....");
	}

	private void initM3UA() throws Exception {
		logger.debug("Initializing M3UA Stack ....");
		M3UAManagementImpl m3uaImpl = new M3UAManagementImpl("Client", "Example");
		m3uaImpl.setTransportManagement(this.sctpManagement);
		this.clientM3UAMgmt = m3uaImpl;
		this.clientM3UAMgmt.start();
		// this.clientM3UAMgmt.removeAllResourses();

		// m3ua as create rc <rc> <ras-name>
		RoutingContext rc = factory.createRoutingContext(new long[] { 100l });
		TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);
		this.clientM3UAMgmt.createAs("AS1", Functionality.AS, ExchangeType.SE, IPSPType.CLIENT, rc, trafficModeType,
				1, null);

		// Step 2 : Create ASP
		this.clientM3UAMgmt.createAspFactory("ASP1", CLIENT_ASSOCIATION_NAME);

		// Step3 : Assign ASP to AS
		Asp asp = this.clientM3UAMgmt.assignAspToAs("AS1", "ASP1");

		// Step 4: Add Route. Remote point code is 2
		this.clientM3UAMgmt.addRoute(SERVER_SPC, -1, -1, "AS1");
		logger.debug("Initialized M3UA Stack ....");

	}

	private void initSCCP() throws Exception {
		logger.debug("Initializing SCCP Stack ....");
		this.sccpStack = new SccpStackImpl("MapLoadClientSccpStack");
		this.sccpStack.setMtp3UserPart(1, (Mtp3UserPart) this.clientM3UAMgmt);

		this.sccpStack.start();
		this.sccpStack.removeAllResourses();

		this.sccpStack.getSccpResource().addRemoteSpc(1, SERVER_SPC, 0, 0);
		this.sccpStack.getSccpResource().addRemoteSsn(1, SERVER_SPC, SSN, 0, false);

		this.sccpStack.getRouter().addMtp3ServiceAccessPoint(1, 1, CLIENT_SPC, NETWORK_INDICATOR, NETWORK_ID);
		this.sccpStack.getRouter().addMtp3Destination(1, 1, SERVER_SPC, SERVER_SPC, 0, 255, 255);
		logger.debug("Initialized SCCP Stack ....");
	}

	private void initTCAP() throws Exception {
		logger.debug("Initializing TCAP Stack ....");
		this.tcapStack = new TCAPStackImpl("ClientTCAPStack", this.sccpStack.getSccpProvider(), SSN);
		this.tcapStack.start();
		this.tcapStack.setInvokeTimeout(30000);
		this.tcapStack.setDialogIdleTimeout(60000);
		this.tcapStack.setMaxDialogs(2000);
		logger.debug("Initialized TCAP Stack ....");
	}

	private void initMAP() throws Exception {
		logger.debug("Initializing MAP Stack ....");
		this.mapStack = new MAPStackImpl("ClientMAPStack", this.tcapStack.getProvider());
		this.mapProvider = this.mapStack.getMAPProvider();

		this.mapProvider.addMAPDialogListener(this);
		this.mapProvider.getMAPServiceSupplementary().addMAPServiceListener(this);

		this.mapProvider.getMAPServiceSupplementary().acivate();

		this.mapStack.start();
		logger.debug("Initialized MAP Stack ....");
	}

	private void initiateUSSD() throws MAPException {

		// First create Dialog

		AddressString destReference = new AddressStringImpl(AddressNature.subscriber_number, NumberingPlan.ISDN, "5555551212");
		MAPDialogSupplementary mapDialog = this.mapProvider.getMAPServiceSupplementary().createNewDialog(
				MAPApplicationContext.getInstance(MAPApplicationContextName.networkUnstructuredSsContext,
						MAPApplicationContextVersion.version2), SCCP_CLIENT_ADDRESS, null, SCCP_SERVER_ADDRESS, destReference);
		
		byte ussdDataCodingScheme = 0x0f;

		// USSD String: *125*+31628839999#
		// The Charset is null, here we let system use default Charset (UTF-7 as
		// explained in GSM 03.38. However if MAP User wants, it can set its own
		// impl of Charset
		USSDString ussdString = this.mapProvider.getMAPParameterFactory().createUSSDString("*125*+31628839999#");

		ISDNAddressString msisdn = this.mapProvider.getMAPParameterFactory().createISDNAddressString(
				AddressNature.international_number, NumberingPlan.ISDN, "31628838002");

		mapDialog.addProcessUnstructuredSSRequest(new CBSDataCodingSchemeImpl(ussdDataCodingScheme), ussdString, null, msisdn);

		// This will initiate the TC-BEGIN with INVOKE component
		mapDialog.send();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogAccept(
	 * org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
	 */
	public void onDialogAccept(MAPDialog mapDialog, MAPExtensionContainer extensionContainer) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format("onDialogAccept for DialogId=%d MAPExtensionContainer=%s",
					mapDialog.getLocalDialogId(), extensionContainer));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogClose(org
	 * .mobicents.protocols.ss7.map.api.MAPDialog)
	 */
	public void onDialogClose(MAPDialog mapDialog) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format("DialogClose for DialogId=%d", mapDialog.getLocalDialogId()));
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogDelimiter
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog)
	 */
	public void onDialogDelimiter(MAPDialog mapDialog) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format("onDialogDelimiter for DialogId=%d", mapDialog.getLocalDialogId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogNotice(
	 * org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic)
	 */
	public void onDialogNotice(MAPDialog mapDialog, MAPNoticeProblemDiagnostic noticeProblemDiagnostic) {
		logger.error(String.format("onDialogNotice for DialogId=%d MAPNoticeProblemDiagnostic=%s ",
				mapDialog.getLocalDialogId(), noticeProblemDiagnostic));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogProviderAbort
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPAbortProviderReason,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPAbortSource,
	 * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
	 */
	public void onDialogProviderAbort(MAPDialog mapDialog, MAPAbortProviderReason abortProviderReason,
			MAPAbortSource abortSource, MAPExtensionContainer extensionContainer) {
		logger.error(String
				.format("onDialogProviderAbort for DialogId=%d MAPAbortProviderReason=%s MAPAbortSource=%s MAPExtensionContainer=%s",
						mapDialog.getLocalDialogId(), abortProviderReason, abortSource, extensionContainer));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogReject(
	 * org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPRefuseReason,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPProviderError,
	 * org.mobicents.protocols.ss7.tcap.asn.ApplicationContextName,
	 * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
	 */
	public void onDialogReject(MAPDialog mapDialog, MAPRefuseReason refuseReason, /* MAPProviderError providerError,*/
			ApplicationContextName alternativeApplicationContext, MAPExtensionContainer extensionContainer) {
		logger.error(String
				.format("onDialogReject for DialogId=%d MAPRefuseReason=%s ApplicationContextName=%s MAPExtensionContainer=%s",
						mapDialog.getLocalDialogId(), refuseReason, alternativeApplicationContext,
						extensionContainer));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogRelease
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog)
	 */
	public void onDialogRelease(MAPDialog mapDialog) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format("onDialogResease for DialogId=%d", mapDialog.getLocalDialogId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogRequest
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * org.mobicents.protocols.ss7.map.api.primitives.AddressString,
	 * org.mobicents.protocols.ss7.map.api.primitives.AddressString,
	 * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
	 */
	public void onDialogRequest(MAPDialog mapDialog, AddressString destReference, AddressString origReference,
			MAPExtensionContainer extensionContainer) {
		if (logger.isDebugEnabled()) {
			logger.debug(String
					.format("onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s MAPExtensionContainer=%s",
							mapDialog.getLocalDialogId(), destReference, origReference, extensionContainer));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogRequestEricsson
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * org.mobicents.protocols.ss7.map.api.primitives.AddressString,
	 * org.mobicents.protocols.ss7.map.api.primitives.AddressString,
	 * org.mobicents.protocols.ss7.map.api.primitives.IMSI,
	 * org.mobicents.protocols.ss7.map.api.primitives.AddressString)
	 */
	public void onDialogRequestEricsson(MAPDialog mapDialog, AddressString destReference, AddressString origReference,
			IMSI arg3, AddressString arg4) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format("onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s ",
					mapDialog.getLocalDialogId(), destReference, origReference));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogTimeout
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog)
	 */
	public void onDialogTimeout(MAPDialog mapDialog) {
		logger.error(String.format("onDialogTimeout for DialogId=%d", mapDialog.getLocalDialogId()));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogUserAbort
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPUserAbortChoice,
	 * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
	 */
	public void onDialogUserAbort(MAPDialog mapDialog, MAPUserAbortChoice userReason,
			MAPExtensionContainer extensionContainer) {
		logger.error(String.format("onDialogUserAbort for DialogId=%d MAPUserAbortChoice=%s MAPExtensionContainer=%s",
				mapDialog.getLocalDialogId(), userReason, extensionContainer));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onProcessUnstructuredSSRequest(org.mobicents
	 * .protocols.ss7.map.api.service
	 * .supplementary.ProcessUnstructuredSSRequest)
	 */
	public void onProcessUnstructuredSSRequest(ProcessUnstructuredSSRequest procUnstrReqInd) {
		// This error condition. Client should never receive the
		// ProcessUnstructuredSSRequestIndication
		logger.error(String.format("onProcessUnstructuredSSRequestIndication for Dialog=%d and invokeId=%d",
				procUnstrReqInd.getMAPDialog().getLocalDialogId(), procUnstrReqInd.getInvokeId()));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onProcessUnstructuredSSResponse(org.mobicents
	 * .protocols.ss7.map.api.service
	 * .supplementary.ProcessUnstructuredSSResponse)
	 */
	public void onProcessUnstructuredSSResponse(ProcessUnstructuredSSResponse procUnstrResInd) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format("Rx ProcessUnstructuredSSResponseIndication.  USSD String=%s", procUnstrResInd
					.getUSSDString().toString()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onUnstructuredSSNotifyRequest(org.mobicents
	 * .protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyRequest)
	 */
	public void onUnstructuredSSNotifyRequest(UnstructuredSSNotifyRequest unstrNotifyInd) {
		// This error condition. Client should never receive the
		// UnstructuredSSNotifyRequestIndication
		logger.error(String.format("onUnstructuredSSNotifyRequestIndication for Dialog=%d and invokeId=%d",
				unstrNotifyInd.getMAPDialog().getLocalDialogId(), unstrNotifyInd.getInvokeId()));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onUnstructuredSSNotifyResponse(org.mobicents
	 * .protocols.ss7.map.api.service
	 * .supplementary.UnstructuredSSNotifyResponse)
	 */
	public void onUnstructuredSSNotifyResponse(UnstructuredSSNotifyResponse unstrNotifyInd) {
		// This error condition. Client should never receive the
		// UnstructuredSSNotifyRequestIndication
		logger.error(String.format("onUnstructuredSSNotifyResponseIndication for Dialog=%d and invokeId=%d",
				unstrNotifyInd.getMAPDialog().getLocalDialogId(), unstrNotifyInd.getInvokeId()));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onUnstructuredSSRequest(org.mobicents.protocols
	 * .ss7.map.api.service.supplementary.UnstructuredSSRequest)
	 */
	public void onUnstructuredSSRequest(UnstructuredSSRequest unstrReqInd) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format("Rx UnstructuredSSRequestIndication. USSD String=%s ", unstrReqInd
					.getUSSDString().toString()));
		}

		MAPDialogSupplementary mapDialog = unstrReqInd.getMAPDialog();

		try {
			byte ussdDataCodingScheme = 0x0f;

			USSDString ussdString = this.mapProvider.getMAPParameterFactory().createUSSDString("1");

			AddressString msisdn = this.mapProvider.getMAPParameterFactory().createAddressString(
					AddressNature.international_number, NumberingPlan.ISDN, "31628838002");

			mapDialog.addUnstructuredSSResponse(unstrReqInd.getInvokeId(), new CBSDataCodingSchemeImpl(ussdDataCodingScheme), ussdString);
			mapDialog.send();

		} catch (MAPException e) {
			logger.error(String.format("Error while sending UnstructuredSSResponse for Dialog=%d",
					mapDialog.getLocalDialogId()));
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onUnstructuredSSResponse(org.mobicents.protocols
	 * .ss7.map.api.service.supplementary.UnstructuredSSResponse)
	 */
	public void onUnstructuredSSResponse(UnstructuredSSResponse unstrResInd) {
		// This error condition. Client should never receive the
		// UnstructuredSSResponseIndication
		logger.error(String.format("onUnstructuredSSResponseIndication for Dialog=%d and invokeId=%d", unstrResInd
				.getMAPDialog().getLocalDialogId(), unstrResInd.getInvokeId()));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onErrorComponent
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog, java.lang.Long,
	 * org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage)
	 */
	public void onErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage mapErrorMessage) {
		logger.error(String.format("onErrorComponent for Dialog=%d and invokeId=%d MAPErrorMessage=%s",
				mapDialog.getLocalDialogId(), invokeId, mapErrorMessage));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onInvokeTimeout
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog, java.lang.Long)
	 */
	public void onInvokeTimeout(MAPDialog mapDialog, Long invokeId) {
		logger.error(String.format("onInvokeTimeout for Dialog=%d and invokeId=%d", mapDialog.getLocalDialogId(), invokeId));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onMAPMessage(org
	 * .mobicents.protocols.ss7.map.api.MAPMessage)
	 */
	public void onMAPMessage(MAPMessage arg0) {
		logger.error(String.format("onMAPMessage for Dialog=%d and invokeId=%d", arg0.getMAPDialog().getLocalDialogId(), arg0.getInvokeId()));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.MAPServiceListener#
	 * onProviderErrorComponent(org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * java.lang.Long,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPProviderError)
	 */
	public void onProviderErrorComponent(MAPDialog mapDialog, Long invokeId/* MAPProviderError providerError */) {
		logger.error(String.format("onProviderErrorComponent for Dialog=%d and invokeId=%d",
				mapDialog.getLocalDialogId(), invokeId /*, providerError */));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onRejectComponent
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog, java.lang.Long,
	 * org.mobicents.protocols.ss7.tcap.asn.comp.Problem)
	 */
	public void onRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem) {
		logger.error(String.format("onRejectComponent for Dialog=%d and invokeId=%d Problem=%s",
				mapDialog.getLocalDialogId(), invokeId, problem));
	}
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onRegisterSSRequest(org.mobicents.protocols
	 * .ss7.map.api.service.supplementary.RegisterSSRequest)
	 */
	public void onRegisterSSRequest(RegisterSSRequest request) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onRegisterSSRequest for Dialog=%d and invokeId=%d",
					request.getMAPDialog().getLocalDialogId(),
					request.getInvokeId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onRegisterSSResponse(org.mobicents.protocols
	 * .ss7.map.api.service.supplementary.RegisterSSResponse)
	 */
	public void onRegisterSSResponse(RegisterSSResponse response) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onRegisterSSResponse for Dialog=%d and invokeId=%d",
					response.getMAPDialog().getLocalDialogId(),
					response.getInvokeId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onEraseSSRequest(org.mobicents.protocols.ss7
	 * .map.api.service.supplementary.EraseSSRequest)
	 */
	public void onEraseSSRequest(EraseSSRequest request) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onEraseSSRequest for Dialog=%d and invokeId=%d", request
							.getMAPDialog().getLocalDialogId(), request
							.getInvokeId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onEraseSSResponse(org.mobicents.protocols.
	 * ss7.map.api.service.supplementary.EraseSSResponse)
	 */
	public void onEraseSSResponse(EraseSSResponse response) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onEraseSSResponse for Dialog=%d and invokeId=%d", response
							.getMAPDialog().getLocalDialogId(), response
							.getInvokeId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onActivateSSRequest(org.mobicents.protocols
	 * .ss7.map.api.service.supplementary.ActivateSSRequest)
	 */
	public void onActivateSSRequest(ActivateSSRequest request) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onActivateSSRequest for Dialog=%d and invokeId=%d",
					request.getMAPDialog().getLocalDialogId(),
					request.getInvokeId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onActivateSSResponse(org.mobicents.protocols
	 * .ss7.map.api.service.supplementary.ActivateSSResponse)
	 */
	public void onActivateSSResponse(ActivateSSResponse response) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onActivateSSResponse for Dialog=%d and invokeId=%d",
					response.getMAPDialog().getLocalDialogId(),
					response.getInvokeId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onDeactivateSSRequest(org.mobicents.protocols
	 * .ss7.map.api.service.supplementary.DeactivateSSRequest)
	 */
	public void onDeactivateSSRequest(DeactivateSSRequest request) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onDeactivateSSRequest for Dialog=%d and invokeId=%d",
					request.getMAPDialog().getLocalDialogId(),
					request.getInvokeId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onDeactivateSSResponse(org.mobicents.protocols
	 * .ss7.map.api.service.supplementary.DeactivateSSResponse)
	 */
	public void onDeactivateSSResponse(DeactivateSSResponse response) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onDeactivateSSResponse for Dialog=%d and invokeId=%d",
					response.getMAPDialog().getLocalDialogId(),
					response.getInvokeId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onInterrogateSSRequest(org.mobicents.protocols
	 * .ss7.map.api.service.supplementary.InterrogateSSRequest)
	 */
	public void onInterrogateSSRequest(InterrogateSSRequest request) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onInterrogateSSResponse for Dialog=%d and invokeId=%d",
					request.getMAPDialog().getLocalDialogId(),
					request.getInvokeId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onInterrogateSSResponse(org.mobicents.protocols
	 * .ss7.map.api.service.supplementary.InterrogateSSResponse)
	 */
	public void onInterrogateSSResponse(InterrogateSSResponse response) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onInterrogateSSResponse for Dialog=%d and invokeId=%d",
					response.getMAPDialog().getLocalDialogId(),
					response.getInvokeId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onGetPasswordRequest(org.mobicents.protocols
	 * .ss7.map.api.service.supplementary.GetPasswordRequest)
	 */
	public void onGetPasswordRequest(GetPasswordRequest request) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onGetPasswordRequest for Dialog=%d and invokeId=%d",
					request.getMAPDialog().getLocalDialogId(),
					request.getInvokeId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onGetPasswordResponse(org.mobicents.protocols
	 * .ss7.map.api.service.supplementary.GetPasswordResponse)
	 */
	public void onGetPasswordResponse(GetPasswordResponse response) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onGetPasswordResponse for Dialog=%d and invokeId=%d",
					response.getMAPDialog().getLocalDialogId(),
					response.getInvokeId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onRegisterPasswordRequest(org.mobicents.protocols
	 * .ss7.map.api.service.supplementary.RegisterPasswordRequest)
	 */
	public void onRegisterPasswordRequest(RegisterPasswordRequest request) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onRegisterPasswordRequest for Dialog=%d and invokeId=%d",
					request.getMAPDialog().getLocalDialogId(),
					request.getInvokeId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
	 * MAPServiceSupplementaryListener
	 * #onRegisterPasswordResponse(org.mobicents.protocols
	 * .ss7.map.api.service.supplementary.RegisterPasswordResponse)
	 */
	public void onRegisterPasswordResponse(RegisterPasswordResponse response) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onRegisterPasswordResponse for Dialog=%d and invokeId=%d",
					response.getMAPDialog().getLocalDialogId(),
					response.getInvokeId()));
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onRejectComponent
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog, java.lang.Long,
	 * org.mobicents.protocols.ss7.tcap.asn.comp.Problem, boolean)
	 */
	public void onRejectComponent(MAPDialog mapDialog, Long invokeId,
			Problem problem, boolean isLocalOriginated) {
		logger.error(String
				.format("onRejectComponent for Dialog=%d and invokeId=%d and problem=%s",
						mapDialog.getLocalDialogId(), invokeId, problem));
	}

	public static void main(String args[]) {
		System.out.println("*************************************");
		System.out.println("***          SctpClient           ***");
		System.out.println("*************************************");
		IpChannelType ipChannelType = IpChannelType.SCTP;
		if (args.length >= 1 && args[0].toLowerCase().equals("tcp"))
			ipChannelType = IpChannelType.TCP;

		final SctpClient client = new SctpClient();

		try {
			client.initializeStack(ipChannelType);

			// Lets pause for 20 seconds so stacks are initialized properly
			Thread.sleep(20000);

			client.initiateUSSD();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}