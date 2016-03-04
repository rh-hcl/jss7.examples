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
import org.mobicents.protocols.ss7.m3ua.As;
import org.mobicents.protocols.ss7.m3ua.Asp;
import org.mobicents.protocols.ss7.m3ua.AspFactory;
import org.mobicents.protocols.ss7.m3ua.M3UAManagement;
import org.mobicents.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.mobicents.protocols.ss7.m3ua.parameter.RoutingContext;
import org.mobicents.protocols.ss7.m3ua.parameter.TrafficModeType;
import org.mobicents.protocols.ss7.map.MAPStackImpl;
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
import org.mobicents.protocols.ss7.mtp.Mtp3UserPart;
import org.mobicents.protocols.ss7.sccp.SccpResource;
import org.mobicents.protocols.ss7.sccp.impl.SccpStackImpl;
import org.mobicents.protocols.ss7.tcap.asn.ApplicationContextName;
import org.mobicents.protocols.ss7.tcap.asn.comp.Problem;

/**
 * @author amit bhayani
 * 
 */
public class SctpServer extends AbstractSctpBase {

	private static Logger logger = Logger.getLogger(SctpServer.class);

	// SCTP
	private ManagementImpl sctpManagement;

	// M3UA
	private M3UAManagement serverM3UAMgmt;

	// SCCP
	private SccpStackImpl sccpStack;

	// MAP
	private MAPStackImpl mapStack;
	private MAPProvider mapProvider;

	private void initSCTP(IpChannelType ipChannelType) throws Exception {
		logger.debug("Initializing SCTP Stack ....");
		this.sctpManagement = new ManagementImpl("Server");
		this.sctpManagement.setSingleThread(true);
		this.sctpManagement.start();
		this.sctpManagement.setConnectDelay(10000);
		this.sctpManagement.removeAllResourses();

		// 1. Create SCTP Server
		sctpManagement.addServer(SERVER_NAME, SERVER_IP, SERVER_PORT, ipChannelType, null);

		// 2. Create SCTP Server Association
		sctpManagement
				.addServerAssociation(CLIENT_IP, CLIENT_PORT, SERVER_NAME, SERVER_ASSOCIATION_NAME, ipChannelType);

		// 3. Start Server
		sctpManagement.startServer(SERVER_NAME);
		logger.debug("Initialized SCTP Stack ....");
	}

	private void initM3UA() throws Exception {
		logger.debug("Initializing M3UA Stack ....");
		M3UAManagementImpl m3uaImpl = new M3UAManagementImpl("Client", "Example");
		m3uaImpl.setTransportManagement(this.sctpManagement);
		this.serverM3UAMgmt = m3uaImpl;
		this.serverM3UAMgmt.start();
		this.serverM3UAMgmt.removeAllResourses();

		// Step 1 : Create App Server

		RoutingContext rc = factory.createRoutingContext(new long[] { 100l });
		TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);
		As as = this.serverM3UAMgmt.createAs("RAS1", Functionality.SGW, ExchangeType.SE, IPSPType.CLIENT, rc,
				trafficModeType, 1, null);

		// Step 2 : Create ASP
		AspFactory aspFactor = this.serverM3UAMgmt.createAspFactory("RASP1", SERVER_ASSOCIATION_NAME);

		// Step3 : Assign ASP to AS
		Asp asp = this.serverM3UAMgmt.assignAspToAs("RAS1", "RASP1");

		// Step 4: Add Route. Remote point code is 2
		this.serverM3UAMgmt.addRoute(CLIENT_SPC, -1, -1, "RAS1");
		logger.debug("Initialized M3UA Stack ....");
	}

	private void initSCCP() throws Exception {
		logger.debug("Initializing SCCP Stack ....");
		this.sccpStack = new SccpStackImpl("MapLoadServerSccpStack");
		this.sccpStack.setMtp3UserPart(1, (Mtp3UserPart) this.serverM3UAMgmt);

		this.sccpStack.start();
		this.sccpStack.removeAllResourses();

		this.sccpStack.getSccpResource().addRemoteSpc(1, CLIENT_SPC, 0, 0);
		this.sccpStack.getSccpResource().addRemoteSsn(1, CLIENT_SPC, SSN, 0, false);

		this.sccpStack.getRouter().addMtp3ServiceAccessPoint(1, 1, SERVER_SPC, NETWORK_INDICATOR, NETWORK_ID);
		this.sccpStack.getRouter().addMtp3Destination(1, 1, CLIENT_SPC, CLIENT_SPC, 0, 255, 255);
		logger.debug("Initialized SCCP Stack ....");
	}

	private void initMAP() throws Exception {
		logger.debug("Initializing MAP Stack ....");
		this.mapStack = new MAPStackImpl("ServerMAPStack", this.sccpStack.getSccpProvider(), SSN);
		this.mapProvider = this.mapStack.getMAPProvider();

		this.mapProvider.addMAPDialogListener(this);
		this.mapProvider.getMAPServiceSupplementary().addMAPServiceListener(this);

		this.mapProvider.getMAPServiceSupplementary().acivate();

		this.mapStack.start();
		logger.debug("Initialized MAP Stack ....");
	}

	protected void initializeStack(IpChannelType ipChannelType) throws Exception {

		this.initSCTP(ipChannelType);

		// Initialize M3UA first
		this.initM3UA();

		// Initialize SCCP
		this.initSCCP();

		// Initialize MAP
		this.initMAP();

		// 7. Start ASP
		serverM3UAMgmt.startAsp("RASP1");

		logger.debug("[[[[[[[[[[    Started SctpServer       ]]]]]]]]]]");
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
			logger.debug(String.format("onDialogClose for Dialog=%d", mapDialog.getLocalDialogId()));
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
	public void onDialogReject(MAPDialog mapDialog, MAPRefuseReason refuseReason, /* MAPProviderError providerError, */
			ApplicationContextName alternativeApplicationContext, MAPExtensionContainer extensionContainer) {
		logger.error(String
				.format("onDialogReject for DialogId=%d MAPRefuseReason=%s MAPProviderError=%s ApplicationContextName=%s MAPExtensionContainer=%s",
						mapDialog.getLocalDialogId(), refuseReason, /* providerError, */ alternativeApplicationContext,
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
			IMSI imsi, AddressString vlr) {
		if (logger.isDebugEnabled()) {
			logger.debug(String.format(
					"onDialogRequestEricsson for DialogId=%d DestinationReference=%s OriginReference=%s ",
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
		if (logger.isDebugEnabled()) {
			logger.debug(String.format("onProcessUnstructuredSSRequestIndication for DialogId=%d. Ussd String=%s",
					procUnstrReqInd.getMAPDialog().getLocalDialogId(), procUnstrReqInd.getUSSDString().toString()));
		}
		try {
			long invokeId = procUnstrReqInd.getInvokeId();

			USSDString ussdStrObj = this.mapProvider.getMAPParameterFactory().createUSSDString(
					"USSD String : Hello World <CR> 1. Balance <CR> 2. Texts Remaining");
			byte ussdDataCodingScheme = (byte) 0x0F;
			MAPDialogSupplementary dialog = procUnstrReqInd.getMAPDialog();

			dialog.setUserObject(invokeId);

			ISDNAddressString msisdn = this.mapProvider.getMAPParameterFactory().createISDNAddressString(
					AddressNature.international_number, NumberingPlan.ISDN, "31628838002");

			dialog.addUnstructuredSSRequest(new CBSDataCodingSchemeImpl(ussdDataCodingScheme), ussdStrObj, null, msisdn);
			dialog.send();
		} catch (MAPException e) {
			logger.error("Error while sending UnstructuredSSRequest ", e);
		}
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
		// Server shouldn't be getting ProcessUnstructuredSSResponseIndication
		logger.error(String.format("onProcessUnstructuredSSResponseIndication for Dialog=%d and invokeId=%d",
				procUnstrResInd.getMAPDialog().getLocalDialogId(), procUnstrResInd.getInvokeId()));
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
		logger.error(String.format("onUnstructuredSSNotifyRequest for Dialog=%d and invokeId=%d", unstrNotifyInd
				.getMAPDialog().getLocalDialogId(), unstrNotifyInd.getInvokeId()));
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
		logger.error(String.format("onUnstructuredSSNotifyResponse for Dialog=%d and invokeId=%d", unstrNotifyInd
				.getMAPDialog().getLocalDialogId(), unstrNotifyInd.getInvokeId()));
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
		// Server shouldn't be getting UnstructuredSSRequestIndication
		logger.error(String.format("onUnstructuredSSRequestIndication for Dialog=%d and invokeId=%d", unstrReqInd
				.getMAPDialog().getLocalDialogId(), unstrReqInd.getInvokeId()));
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
		if (logger.isDebugEnabled()) {
			logger.debug(String.format("onUnstructuredSSResponseIndication for DialogId=%d Ussd String=%s", unstrResInd
					.getMAPDialog().getLocalDialogId(), unstrResInd.getUSSDString().toString()));
		}
		try {
			USSDString ussdStrObj = this.mapProvider.getMAPParameterFactory().createUSSDString("Your balance is 500");
			byte ussdDataCodingScheme = (byte) 0x0F;
			MAPDialogSupplementary dialog = unstrResInd.getMAPDialog();

			AddressString msisdn = this.mapProvider.getMAPParameterFactory().createAddressString(
					AddressNature.international_number, NumberingPlan.ISDN, "31628838002");

			dialog.addProcessUnstructuredSSResponse(((Long) dialog.getUserObject()).longValue(), new CBSDataCodingSchemeImpl(ussdDataCodingScheme),
					ussdStrObj);
			dialog.close(false);
		} catch (MAPException e) {
			logger.error("Error while sending UnstructuredSSRequest ", e);
		}
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
		// TODO Auto-generated method stub
		logger.error(String.format("onMAPMessage for invokeId=%d", arg0.getInvokeId()));

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.MAPServiceListener#
	 * onProviderErrorComponent(org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * java.lang.Long,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPProviderError)
	 */
	public void onProviderErrorComponent(MAPDialog mapDialog, Long invokeId /*, MAPProviderError providerError*/) {
		logger.error(String.format("onProviderErrorComponent for Dialog=%d and invokeId=%d",
				mapDialog.getLocalDialogId(), invokeId));
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
				.format("onRejectComponent for Dialog=%d and InvokeId=%d and Problem=%s",
						mapDialog.getLocalDialogId(), invokeId, problem));
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		System.out.println("*************************************");
		System.out.println("***          SctpServer           ***");
		System.out.println("*************************************");
		IpChannelType ipChannelType = IpChannelType.SCTP;
		if (args.length >= 1 && args[0].toLowerCase().equals("tcp"))
			ipChannelType = IpChannelType.TCP;

		final SctpServer server = new SctpServer();
		try {
			server.initializeStack(ipChannelType);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
