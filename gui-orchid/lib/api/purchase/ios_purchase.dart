import 'dart:async';
import 'package:in_app_purchase/store_kit_wrappers.dart';
import 'package:orchid/util/units.dart';
import '../orchid_api.dart';
import '../orchid_log_api.dart';
import 'orchid_pac.dart';
import 'orchid_pac_server.dart';
import 'orchid_pac_transaction.dart';
import 'orchid_purchase.dart';

class IOSOrchidPurchaseAPI extends OrchidPurchaseAPI
    implements SKTransactionObserverWrapper {

  IOSOrchidPurchaseAPI() : super.internal();

  /// Default prod service endpoint configuration.
  /// May be overridden in configuration with e.g.
  /// 'pacs = {
  ///    enabled: true,
  ///    url: 'https://xxx.amazonaws.com/dev',
  ///    debug: true
  ///  }'
  static PacApiConfig prodAPIConfig =
      PacApiConfig(url: 'https://api.orchid.com/pac');

  // The raw value from the iOS API
  static const int SKErrorPaymentCancelled = 2;

  /// Return the API config allowing overrides from configuration.
  @override
  Future<PacApiConfig> apiConfig() async {
    return OrchidPurchaseAPI.apiConfigWithOverrides(prodAPIConfig);
  }

  @override
  Future<void> initStoreListenerImpl() async {
    SKPaymentQueueWrapper().setTransactionObserver(this);
  }

  @override
  Future<void> purchaseImpl(PAC pac) async {
    var payment = SKPaymentWrapper(productIdentifier: pac.productId);
    try {
      log("iap: add payment to queue");
      await SKPaymentQueueWrapper().addPayment(payment);
    } catch (err) {
      log("Error adding payment to queue: $err");
      // The exception will be handled by the calling UI. No tx started.
      rethrow;
    }
  }

  /// Gather results of an in-app purchase.
  @override
  void updatedTransactions(
      {List<SKPaymentTransactionWrapper> transactions}) async {
    log("iap: received (${transactions.length}) updated transactions");
    for (SKPaymentTransactionWrapper tx in transactions) {
      switch (tx.transactionState) {
        case SKPaymentTransactionStateWrapper.purchasing:
          log("iap: IAP purchasing state");
          if (PacTransaction.shared.get() == null) {
            log("iap: Unexpected purchasing state.");
            // TODO: We'd like to salvage the receipt but what identity should we use?
            // PacAddBalanceTransaction.pending(
            //     signer: signer, productId: tx.payment.productIdentifier).save();
          }
          break;

        case SKPaymentTransactionStateWrapper.restored:
          log("iap: iap purchase restored?");
          // Are we getting this on a second purchase attempt that we dropped?
          // Attempting to just handle it as a new purchase for now.
          _completeIAPTransaction(tx);
          break;

        case SKPaymentTransactionStateWrapper.purchased:
          log("iap: IAP purchased state");
          try {
            await SKPaymentQueueWrapper().finishTransaction(tx);
          } catch (err) {
            log("iap: error finishing purchased tx: $err");
          }
          _completeIAPTransaction(tx);
          break;

        case SKPaymentTransactionStateWrapper.failed:
          log("iap: IAP failed state");

          log("iap: finishing failed tx");
          try {
            await SKPaymentQueueWrapper().finishTransaction(tx);
          } catch (err) {
            log("iap: error finishing cancelled tx: $err");
          }

          if (tx.error?.code == SKErrorPaymentCancelled) {
            log("iap: was cancelled");
            PacTransaction.shared.clear();
          } else {
            log("iap: IAP Failed, ${tx.toString()} error: type=${tx.error.runtimeType}, code=${tx.error.code}, userInfo=${tx.error.userInfo}, domain=${tx.error.domain}");
            var pacTx = await PacTransaction.shared.get();
            pacTx.error("iap failed").save();
          }
          break;

        case SKPaymentTransactionStateWrapper.deferred:
          log("iap: iap deferred");
          break;
      }
    }
  }

  // The IAP is complete, update AML and the pending transaction status.
  Future _completeIAPTransaction(SKPaymentTransactionWrapper tx) async {
    // Record the purchase for rate limiting
    OrchidPurchaseAPI.addPurchaseToRateLimit(tx.payment.productIdentifier);

    // Get the receipt
    try {
      var receipt = await SKReceiptManager.retrieveReceiptData();

      // If the receipt is null, try to refresh it.
      // (This might happen if there was a purchase in flight during an upgrade.)
      if (receipt == null) {
        try {
          await SKRequestMaker().startRefreshReceiptRequest();
        } catch (err) {
          log("iap: Error in refresh receipt request");
        }
        receipt = await SKReceiptManager.retrieveReceiptData();
      }

      // If the receipt is still null there's not much we can do.
      if (receipt == null) {
        log("iap: Completed purchase but no receipt found! Clearing transaction.");
        await PacTransaction.shared.clear();
        return;
      }

      // Pass the receipt to the pac system
      OrchidPACServer().advancePACTransactionsWithReceipt(receipt, ReceiptType.ios);
    } catch (err) {
      log("iap: error getting receipt data for completed iap: $err");
    }
  }

  static Map<String, PAC> productsCached;

  @override
  Future<Map<String, PAC>> requestProducts({bool refresh = false}) async {
    if (OrchidAPI.mockAPI) {
      return OrchidPurchaseAPI.mockPacs();
    }
    if (productsCached != null && !refresh) {
      log("iap: returning cached products");
      return productsCached;
    }

    var productIds = OrchidPurchaseAPI.pacProductIds;
    log("iap: product ids requested: $productIds");
    SkProductResponseWrapper productResponse =
        await SKRequestMaker().startProductRequest(productIds);
    log("iap: product response: ${productResponse.products.map((p) => p.productIdentifier)}");

    var toPAC = (SKProductWrapper prod) {
      double localizedPrice = double.parse(prod.price);
      String currencyCode = prod.priceLocale.currencyCode;
      String currencySymbol = prod.priceLocale.currencySymbol;
      var productId = prod.productIdentifier;
      return PAC(
        productId: productId,
        localPrice: localizedPrice,
        localCurrencyCode: currencyCode,
        localCurrencySymbol: currencySymbol,
        usdPriceExact: OrchidPurchaseAPI.usdPriceForProduct(productId),
      );
    };

    var pacs = productResponse.products.map(toPAC).toList();
    Map<String, PAC> products = {for (var pac in pacs) pac.productId: pac};
    productsCached = products;
    log("iap: returning products");
    return products;
  }

  @override
  bool shouldAddStorePayment(
      {SKPaymentWrapper payment, SKProductWrapper product}) {
    return true;
  }

  @override
  void paymentQueueRestoreCompletedTransactionsFinished() {}

  @override
  void removedTransactions({List<SKPaymentTransactionWrapper> transactions}) {
    log("removed transactions: $transactions");
  }

  @override
  void restoreCompletedTransactionsFailed({SKError error}) {
    log("restore failed");
  }
}

